#include "stdafx.h"
#include "IoRequest.h"

LONG IoRequest::hasWritten = 0x0;

// Statics initialization
const DWORD IoRequest::invalidIoctlErrorCodes[] = {
    ERROR_INVALID_FUNCTION,
    ERROR_NOT_SUPPORTED,
    ERROR_INVALID_PARAMETER,
    ERROR_NO_SYSTEM_RESOURCES
};
const DWORD IoRequest::invalidBufSizeErrorCodes[] = {
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_BAD_LENGTH,
};

// Simple constructors
IoRequest::IoRequest(HANDLE hDev) : hDev(hDev), outBuf(DEFAULT_OUTLEN+CANARY_SIZE)
{
    ZeroMemory(&overlp, sizeof(overlp));
}

IoRequest::IoRequest(HANDLE hDev, DWORD code) : hDev(hDev), iocode(code), outBuf(DEFAULT_OUTLEN+CANARY_SIZE)
{
    ZeroMemory(&overlp, sizeof(overlp));
}

VOID IoRequest::reset()
{
    ZeroMemory(&overlp, sizeof(overlp));
    return;
}

IoRequest::~IoRequest()
{
    return;
}

BOOL IoRequest::allocBuffers(DWORD inSize, DWORD outSize)
{
    BOOL bResult=TRUE;
    try {
        inBuf.resize(inSize);
        outBuf.resize(outSize+CANARY_SIZE);
        bResult = TRUE;
    }
    catch(bad_alloc) {
        bResult = FALSE;
    }
    return bResult;
}

BOOL IoRequest::addCanary()
{
    DWORD i;
    DWORD outBufSize = getOutputBufferLength();
    DWORD outBufRealSize = outBufSize + CANARY_SIZE;
    for (i = outBufSize; i < outBufRealSize; i++) {
        outBuf[i] = CANARY;
    }
    return TRUE;
}

BOOL IoRequest::checkForIL()
{
    BOOL bResult = FALSE;
    DWORD i;
    DWORD outBufSize = getOutputBufferLength();
    DWORD outBufRealSize = outBufSize + CANARY_SIZE;

    if (IL_CHECK & 0x1) {
        for (i = outBufSize; i < outBufRealSize; i++) {
            if (outBuf[i] != CANARY) {
                bResult = TRUE;
                TPRINT(VERBOSITY_ALL, _T("Canary value corrupted (%p). Potential infoleak recorded.\n"), *(PVOID*)(&(outBuf)[outBufSize]));
                if (!(InterlockedOr(&hasWritten, (LONG)0x1) & 0x1)) {
                    bResult = writeIL(*(PVOID*)(&(outBuf)[outBufSize]), TRUE);
                }
                break;
            }
        }
    }

    //Check outbuf for things that look like kernel pointers
    // TODO: Make this work for 32 bit
    if (IL_CHECK & 0x2 && outBufSize >= sizeof(PVOID)) {
        for (i = 0; i < outBufRealSize - sizeof(PVOID); i++) {
            if (*(PDWORD)(&(outBuf)[i]) > 0xFFFFF6FF) {
                bResult = TRUE;
                TPRINT(VERBOSITY_ALL, _T("Possible kernel pointer in buffer (%p). Potential infoleak recorded.\n"), *(PVOID*)(&(outBuf)[i]));
                break;
                if (!(InterlockedOr(&hasWritten, (LONG)0x2) & 0x2)) {
                    bResult = writeIL(*(PVOID*)(&(outBuf)[i]), FALSE);
                }
            }
        }
    }

    return bResult;
}

BOOL IoRequest::writeIL(PVOID ptr, BOOL isCanary)
{
    BOOL bResult = FALSE;
    ofstream logFile;
    tstring filename = (isCanary) ? L"canary_" : L"lookalike_";
    filename.append(Dibf::fileName);
    // Open the log file
    logFile.open((LPCTSTR)filename);
    if (logFile.good()) {
        logFile << "LogFile Name: " << Dibf::fileName << "\n";
        logFile << "dwIoControlCode: " << iocode << "\n";
        logFile << "nInBufferSize: " << getInputBufferLength() << "\n";
        logFile << "nOutBufferSize: " << getOutputBufferLength() << "\n";
        TPRINT(VERBOSITY_INFO, _T("Successfully written metadata for iocode: %#.8x leak to log file %s\n"), iocode, (LPCTSTR)filename);
        logFile.close();
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Error creating/opening metadata log file %s\n"), (LPCTSTR)filename);
    }

    tstring filenamein = L"inbuf_";
    filenamein.append(filename);
    logFile.open((LPCTSTR)filenamein, ios::out | ios::binary);
    if (logFile.good()) {
        std::copy(inBuf.begin(), inBuf.end(), std::ostreambuf_iterator<char>(logFile));
        TPRINT(VERBOSITY_INFO, _T("Successfully written inbuf for leak to log file %s\n"), (LPCTSTR)filenamein);
        logFile.close();
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Error creating/opening inbuf log file %s\n"), (LPCTSTR)filenamein);
    }

    tstring filenameout = L"outbuf_";
    filenameout.append(filename);
    logFile.open((LPCTSTR)filenameout, ios::out | ios::binary);
    if (logFile.good()) {
        std::copy(outBuf.begin(), outBuf.end(), std::ostreambuf_iterator<char>(logFile));
        TPRINT(VERBOSITY_INFO, _T("Successfully written outbuf (flagged ptr: 0x%p) for leak to log file %s\n"), ptr, (LPCTSTR)filenameout);
        logFile.close();
        bResult = TRUE;
    }
    else {
        TPRINT(VERBOSITY_ERROR, _T("Error creating/opening outbuf log file %s\n"), (LPCTSTR)filenameout);
        bResult = FALSE;
    }
    return bResult;
}

BOOL IoRequest::sendRequest(BOOL async, DWORD &lastError)
{
    BOOL bResult;
    DWORD dwBytes;

    bResult = DeviceIoControl(hDev, iocode, inBuf.data(), getInputBufferLength(), outBuf.data(), getOutputBufferLength(), &dwBytes, async ? &overlp : NULL);
    if(!bResult) {
        lastError = GetLastError();
    }
    return bResult;
}

BOOL IoRequest::sendSync()
{
    BOOL bResult=FALSE;
    DWORD error;

    if(sendRequest(FALSE, error)) {
        bResult=TRUE;
    }
    return bResult;
}

DWORD IoRequest::sendAsync()
{
    DWORD error, dwResult=DIBF_ERROR;

    if(sendRequest(TRUE, error)) {
        dwResult=DIBF_SUCCESS;
    }
    else {
        if(ERROR_IO_PENDING==error) {
            dwResult=DIBF_PENDING;
        }
    }
    return dwResult;
}

BOOL IoRequest::testSendForValidRequest(BOOL deep, DWORD & lastError)
{
    BOOL bResult=FALSE;
    DWORD dwSize;
    LPTSTR errormessage;

    // If deep, attempt inlen 0-256 otherwise just try inlen 32
    // outlen is always 256 (usually there's only an upper bound)
    for(dwSize=deep?0:DEEP_BF_MAX; !bResult&&dwSize<=DEEP_BF_MAX; dwSize+=4) {
        if(allocBuffers(dwSize, DEFAULT_OUTLEN)) {
            bResult = sendRequest(FALSE, lastError) || IsValidCode(lastError);
        }
    }
    // Print return code indicating valid IOCTL code
    if(bResult) {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, lastError, 0, (LPTSTR)&errormessage, 4, NULL);
        if(errormessage) {
            TPRINT(VERBOSITY_ALL, _T("Found IOCTL: %#.8x failed with error %#.8x - %s"), iocode, lastError, errormessage);
            LocalFree(errormessage);
        }
        else {
            TPRINT(VERBOSITY_ALL, _T("Found IOCTL: %#.8x failed with error %#.8x\n"), iocode, lastError);
        }
    }
    return bResult;
}

BOOL IoRequest::testSendForValidBufferSize(DWORD testSize)
{
    BOOL bResult=FALSE;
    DWORD lastError;
    LPTSTR errormessage;

    if(allocBuffers(testSize, DEFAULT_OUTLEN)) {
        bResult = sendRequest(FALSE, lastError) || IsValidSize(lastError);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, lastError, 0, (LPTSTR)&errormessage, 4, NULL);
    } // if allocbuffers
    return bResult;
}

BOOL IoRequest::fuzz(FuzzingProvider* fp, mt19937* prng)
{
    BOOL bResult1=FALSE, bResult2=FALSE;
    bResult1 = addCanary();
    bResult2 = fp->GetRandomIoctlAndBuffer(iocode, inBuf, prng);
    return (bResult1 && bResult2);
}