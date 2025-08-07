#pragma once
#include <cstdint>
#include <type_traits>
#include <bit>
#include <string>
#include "byteswap.h"

#ifdef _WIN32
    #include <windows.h>
#endif

// real win32 handles will never use the upper bits unless something goes really wrong
#define CHECK_GUEST_HANDLE(HANDLE) (((HANDLE) & 0x80000000) == 0x80000000)
#define GUEST_HANDLE(HANDLE) ((HANDLE) | 0x80000000)
#define HOST_HANDLE(HANDLE) ((HANDLE) & ~0x80000000)

// Return true to free the associated memory
typedef bool(*TypeDestructor_t)(void*);

template<typename T>
bool DestroyObject(void* obj)
{
    static_cast<T*>(obj)->~T();
    return true;
}

template<typename T>
struct be
{
    T value;

    be() : value(0)
    {
    }

    be(const T v)
    {
        set(v);
    }

    static T byteswap(T value)
    {
        if constexpr (std::is_same_v<T, double>)
        {
            const uint64_t swapped = ByteSwap(*reinterpret_cast<uint64_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else if constexpr (std::is_same_v<T, float>)
        {
            const uint32_t swapped = ByteSwap(*reinterpret_cast<uint32_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else if constexpr (std::is_enum_v<T>)
        {
            const std::underlying_type_t<T> swapped = ByteSwap(*reinterpret_cast<std::underlying_type_t<T>*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else
        {
            return ByteSwap(value);
        }
    }

    void set(const T v)
    {
        value = byteswap(v);
    }

    T get() const
    {
        return byteswap(value);
    }

    be& operator| (T value)
    {
        set(get() | value);
        return *this;
    }

    be& operator& (T value)
    {
        set(get() & value);
        return *this;
    }

    operator T() const
    {
        return get();
    }

    be& operator=(T v)
    {
        set(v);
        return *this;
    }

    be& operator++ ()
    {
        set(get() + 1);
        return *this;
    }

    be operator++ (int)
    {
        be old = *this;
        set(get() + 1);
        return old;
    }

    be& operator-- ()
    {
        set(get() - 1);
        return *this;
    }

    be operator-- (int)
    {
        be old = *this;
        set(get() - 1);
        return old;
    }
};

extern "C" void* MmGetHostAddress(uint32_t ptr);
template<typename T>
struct xpointer
{
    be<uint32_t> ptr;

    xpointer() : ptr(0)
    {
    }

    xpointer(T* p) : ptr(p != nullptr ? (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(MmGetHostAddress(0))) : 0)
    {
    }

    T* get() const
    {
        if (!ptr.value)
        {
            return nullptr;
        }

        return reinterpret_cast<T*>(MmGetHostAddress(ptr));
    }

    operator T* () const
    {
        return get();
    }

    T* operator->() const
    {
        return get();
    }
};

template<typename TGuest>
struct HostObject
{
    typedef TGuest guest_type;
};

struct _XLIST_ENTRY;
typedef _XLIST_ENTRY XLIST_ENTRY;
typedef xpointer<XLIST_ENTRY> PXLIST_ENTRY;

typedef struct _IMAGE_CE_RUNTIME_FUNCTION
{
    uint32_t BeginAddress;

    union 
    {
        uint32_t Data;
        struct
        {
            uint32_t PrologLength : 8;
            uint32_t FunctionLength : 22;
            uint32_t ThirtyTwoBit : 1;
            uint32_t ExceptionFlag : 1;
        };
    };
} IMAGE_CE_RUNTIME_FUNCTION;

static_assert(sizeof(IMAGE_CE_RUNTIME_FUNCTION) == 8);

typedef struct _XLIST_ENTRY
{
    be<uint32_t> Flink;
    be<uint32_t> Blink;
} XLIST_ENTRY;

typedef struct _XDISPATCHER_HEADER
{
    union
    {
        struct
        {
            uint8_t Type;
            union
            {
                uint8_t Abandoned;
                uint8_t Absolute;
                uint8_t NpxIrql;
                uint8_t Signalling;
            };
            union
            {
                uint8_t Size;
                uint8_t Hand;
            };
            union
            {
                uint8_t Inserted;
                uint8_t DebugActive;
                uint8_t DpcActive;
            };
        };
        be<uint32_t> Lock;
    };

    be<uint32_t> SignalState;
    XLIST_ENTRY WaitListHead;
} XDISPATCHER_HEADER, * XPDISPATCHER_HEADER;

typedef struct _XRTL_CRITICAL_SECTION
{
    XDISPATCHER_HEADER Header;
    be<int32_t> LockCount;
    be<int32_t> RecursionCount;
    be<uint32_t> OwningThread;
} XRTL_CRITICAL_SECTION;

typedef struct _XANSI_STRING {
    be<uint16_t> Length;
    be<uint16_t> MaximumLength;
    xpointer<char> Buffer;
} XANSI_STRING;

typedef struct _XOBJECT_ATTRIBUTES
{
    be<uint32_t> RootDirectory;
    xpointer<XANSI_STRING> Name;
    xpointer<void> Attributes;
} XOBJECT_ATTRIBUTES;

typedef XDISPATCHER_HEADER XKEVENT;

typedef struct _XIO_STATUS_BLOCK
{
    union {
        be<uint32_t> Status;
        be<uint32_t> Pointer;
    };
    be<uint32_t> Information;
} XIO_STATUS_BLOCK;

typedef struct _XOVERLAPPED {
    be<uint32_t> Internal;
    be<uint32_t> InternalHigh;
    be<uint32_t> Offset;
    be<uint32_t> OffsetHigh;
    be<uint32_t> hEvent;
} XOVERLAPPED;

// this name is so dumb
typedef struct _XXOVERLAPPED {
    union
    {
        struct
        {
            be<uint32_t> Error;
            be<uint32_t> Length;
        };

        struct
        {
            uint32_t InternalLow;
            uint32_t InternalHigh;
        };
    };
    uint32_t InternalContext;
    be<uint32_t> hEvent;
    be<uint32_t> pCompletionRoutine;
    be<uint32_t> dwCompletionContext;
    be<uint32_t> dwExtendedError;
} XXOVERLAPPED, *PXXOVERLAPPED;

static_assert(sizeof(_XXOVERLAPPED) == 0x1C);

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-memorystatus
typedef struct _XMEMORYSTATUS {
    be<uint32_t> dwLength;
    be<uint32_t> dwMemoryLoad;
    be<uint32_t> dwTotalPhys;
    be<uint32_t> dwAvailPhys;
    be<uint32_t> dwTotalPageFile;
    be<uint32_t> dwAvailPageFile;
    be<uint32_t> dwTotalVirtual;
    be<uint32_t> dwAvailVirtual;
} XMEMORYSTATUS, * XLPMEMORYSTATUS;

typedef struct _XVIDEO_MODE
{
    be<uint32_t> DisplayWidth;
    be<uint32_t> DisplayHeight;
    be<uint32_t> IsInterlaced;
    be<uint32_t> IsWidescreen;
    be<uint32_t> IsHighDefinition;
    be<uint32_t> RefreshRate;
    be<uint32_t> VideoStandard;
    be<uint32_t> Unknown4A;
    be<uint32_t> Unknown01;
    be<uint32_t> reserved[3];
} XVIDEO_MODE;

typedef struct _XKSEMAPHORE
{
    XDISPATCHER_HEADER Header;
    be<uint32_t> Limit;
} XKSEMAPHORE;

typedef struct _XUSER_SIGNIN_INFO {
    be<uint64_t> xuid;
    be<uint32_t> dwField08;
    be<uint32_t> SigninState;
    be<uint32_t> dwField10;
    be<uint32_t> dwField14;
    char Name[16];
} XUSER_SIGNIN_INFO;

typedef struct _XTIME_FIELDS
{
    be<uint16_t> Year;
    be<uint16_t> Month;
    be<uint16_t> Day;
    be<uint16_t> Hour;
    be<uint16_t> Minute;
    be<uint16_t> Second;
    be<uint16_t> Milliseconds;
    be<uint16_t> Weekday;
} XTIME_FIELDS, * PXTIME_FIELDS;

// Content types
#define XCONTENTTYPE_SAVEDATA 1
#define XCONTENTTYPE_DLC      2
#define XCONTENTTYPE_RESERVED 3

#define XCONTENT_NEW      1
#define XCONTENT_EXISTING 2

#define XCONTENT_MAX_DISPLAYNAME 128
#define XCONTENT_MAX_FILENAME    42
#define XCONTENTDEVICE_MAX_NAME  27

typedef struct _XCONTENT_DATA
{
    be<uint32_t> DeviceID;
    be<uint32_t> dwContentType;
    be<uint16_t> szDisplayName[XCONTENT_MAX_DISPLAYNAME];
    char szFileName[XCONTENT_MAX_FILENAME];
} XCONTENT_DATA, * PXCONTENT_DATA;

typedef struct _XHOSTCONTENT_DATA : _XCONTENT_DATA
{
    // This is a host exclusive type so we don't care what goes on
    std::string szRoot{};
} XHOSTCONTENT_DATA, *PXHOSTCONTENT_DATA;


#define XCONTENTDEVICETYPE_HDD 1
#define XCONTENTDEVICETYPE_MU 2

typedef struct _XDEVICE_DATA
{
    be<uint32_t> DeviceID;
    be<uint32_t> DeviceType;
    be<uint64_t> ulDeviceBytes;
    be<uint64_t> ulDeviceFreeBytes;
    be<uint16_t> wszName[XCONTENTDEVICE_MAX_NAME];
} XDEVICE_DATA, *PXDEVICE_DATA;

// Direct reflection of XInput structures

#define XAMINPUT_DEVTYPE_GAMEPAD          0x01
#define XAMINPUT_DEVSUBTYPE_GAMEPAD       0x01

#define XAMINPUT_GAMEPAD_DPAD_UP          0x0001
#define XAMINPUT_GAMEPAD_DPAD_DOWN        0x0002
#define XAMINPUT_GAMEPAD_DPAD_LEFT        0x0004
#define XAMINPUT_GAMEPAD_DPAD_RIGHT       0x0008
#define XAMINPUT_GAMEPAD_START            0x0010
#define XAMINPUT_GAMEPAD_BACK             0x0020
#define XAMINPUT_GAMEPAD_LEFT_THUMB       0x0040
#define XAMINPUT_GAMEPAD_RIGHT_THUMB      0x0080
#define XAMINPUT_GAMEPAD_LEFT_SHOULDER    0x0100
#define XAMINPUT_GAMEPAD_RIGHT_SHOULDER   0x0200
#define XAMINPUT_GAMEPAD_A                0x1000
#define XAMINPUT_GAMEPAD_B                0x2000
#define XAMINPUT_GAMEPAD_X                0x4000
#define XAMINPUT_GAMEPAD_Y                0x8000

typedef struct _XAMINPUT_GAMEPAD
{
    uint16_t                            wButtons;
    uint8_t                             bLeftTrigger;
    uint8_t                             bRightTrigger;
    int16_t                             sThumbLX;
    int16_t                             sThumbLY;
    int16_t                             sThumbRX;
    int16_t                             sThumbRY;
} XAMINPUT_GAMEPAD, *PXAMINPUT_GAMEPAD;

typedef struct _XAMINPUT_VIBRATION
{
    uint16_t                            wLeftMotorSpeed;
    uint16_t                            wRightMotorSpeed;
} XAMINPUT_VIBRATION, * PXAMINPUT_VIBRATION;

typedef struct _XAMINPUT_CAPABILITIES
{
    uint8_t                             Type;
    uint8_t                             SubType;
    uint16_t                            Flags;
    XAMINPUT_GAMEPAD                    Gamepad;
    XAMINPUT_VIBRATION                  Vibration;
} XAMINPUT_CAPABILITIES, * PXAMINPUT_CAPABILITIES;

typedef struct _XAMINPUT_STATE
{
    uint32_t                            dwPacketNumber;
    XAMINPUT_GAMEPAD                    Gamepad;
} XAMINPUT_STATE, * PXAMINPUT_STATE;
