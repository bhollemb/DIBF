#pragma once
#include "stdafx.h"
#include "common.h"
#include "FuzzingProvider.h"
#include "dibf.h"

#define MAX_IOCTLS 512
#define DEEP_BF_MAX ((DWORD)32)
#define DEFAULT_OUTLEN ((DWORD)1024)
#define IL_CHECK 0x3 // MASK, 0x1 == Do canary check, 0x2 == Do KP search, 0x3 == Both
#define CANARY_SIZE 8 // Making this less than sizeof(PVOID) may end poorly
#define CANARY 0x41



#define IsValidCode(ERROR) (!IsInCArray<_countof(invalidIoctlErrorCodes)>(invalidIoctlErrorCodes, ERROR))
#define IsValidSize(ERROR) (!IsInCArray<_countof(invalidBufSizeErrorCodes)>(invalidBufSizeErrorCodes, ERROR))

class IoRequest
{
public:
    IoRequest();
    IoRequest(HANDLE);
    IoRequest(HANDLE, DWORD);
    ~IoRequest();
    OVERLAPPED overlp; // oop?
    DWORD GetIoCode() {return iocode;}
    VOID SetIoCode(DWORD iocode) {this->iocode=iocode;}
    BOOL testSendForValidRequest(BOOL, DWORD&);
    BOOL testSendForValidBufferSize(DWORD);
    VOID reset();
    BOOL sendSync();
    DWORD sendAsync();
    BOOL checkForIL();
    BOOL fuzz(FuzzingProvider*, mt19937*);
private:
    // Static arrays of known interesting errors
    static const DWORD invalidIoctlErrorCodes[];
    static const DWORD invalidBufSizeErrorCodes[];
    static LONG hasWritten;    // Mask, 0x0=none, 0x1=Canary, 0x2=Lookalike
    // Members
    HANDLE hDev;
    DWORD iocode;
    vector<UCHAR> inBuf;
    vector<UCHAR> outBuf;
    // Functions
    BOOL addCanary();
    BOOL writeIL(PVOID, BOOL);
    BOOL sendRequest(BOOL, DWORD&);
    BOOL allocBuffers(DWORD, DWORD);
    DWORD getInputBufferLength(){return inBuf.size()*sizeof(UCHAR);}
    DWORD getOutputBufferLength(){return (outBuf.size()*sizeof(UCHAR))-CANARY_SIZE;}
};