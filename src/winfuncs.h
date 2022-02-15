#include <windows.h>

#ifdef BOF
// if compiling a BOF resolve dynamically
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(PVOID, PVOID, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI DWORD WINAPI ADVAPI32$GetLengthSid(PVOID);
#else

#include <stdio.h>
#define ADVAPI32$LookupPrivilegeValueW LookupPrivilegeValueW 
#define ADVAPI32$GetLengthSid GetLengthSid
#define KERNEL32$GetLastError GetLastError
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0

// Credits to @EspressoCake
// https://github.com/EspressoCake/Toggle_Token_Privileges_BOF/blob/main/src/main.c

#define SE_CREATE_TOKEN_NAME_W                         L"SeCreateTokenPrivilege"
#define SE_ASSIGNPRIMARYTOKEN_NAME_W                   L"SeAssignPrimaryTokenPrivilege"
#define SE_LOCK_MEMORY_NAME_W                          L"SeLockMemoryPrivilege"
#define SE_INCREASE_QUOTA_NAME_W                       L"SeIncreaseQuotaPrivilege"
#define SE_UNSOLICITED_INPUT_NAME_W                    L"SeUnsolicitedInputPrivilege"
#define SE_MACHINE_ACCOUNT_NAME_W                      L"SeMachineAccountPrivilege"
#define SE_TCB_NAME_W                                  L"SeTcbPrivilege"
#define SE_SECURITY_NAME_W                             L"SeSecurityPrivilege"
#define SE_TAKE_OWNERSHIP_NAME_W                       L"SeTakeOwnershipPrivilege"
#define SE_LOAD_DRIVER_NAME_W                          L"SeLoadDriverPrivilege"
#define SE_SYSTEM_PROFILE_NAME_W                       L"SeSystemProfilePrivilege"
#define SE_SYSTEMTIME_NAME_W                           L"SeSystemtimePrivilege"
#define SE_PROF_SINGLE_PROCESS_NAME_W                  L"SeProfileSingleProcessPrivilege"
#define SE_INC_BASE_PRIORITY_NAME_W                    L"SeIncreaseBasePriorityPrivilege"
#define SE_CREATE_PAGEFILE_NAME_W                      L"SeCreatePagefilePrivilege"
#define SE_CREATE_PERMANENT_NAME_W                     L"SeCreatePermanentPrivilege"
#define SE_BACKUP_NAME_W                               L"SeBackupPrivilege"
#define SE_RESTORE_NAME_W                              L"SeRestorePrivilege"
#define SE_SHUTDOWN_NAME_W                             L"SeShutdownPrivilege"
#define SE_DEBUG_NAME_W                                L"SeDebugPrivilege"
#define SE_AUDIT_NAME_W                                L"SeAuditPrivilege"
#define SE_SYSTEM_ENVIRONMENT_NAME_W                   L"SeSystemEnvironmentPrivilege"
#define SE_CHANGE_NOTIFY_NAME_W                        L"SeChangeNotifyPrivilege"
#define SE_REMOTE_SHUTDOWN_NAME_W                      L"SeRemoteShutdownPrivilege"
#define SE_UNDOCK_NAME_W                               L"SeUndockPrivilege"
#define SE_SYNC_AGENT_NAME_W                           L"SeSyncAgentPrivilege"
#define SE_ENABLE_DELEGATION_NAME_W                    L"SeEnableDelegationPrivilege"
#define SE_MANAGE_VOLUME_NAME_W                        L"SeManageVolumePrivilege"
#define SE_IMPERSONATE_NAME_W                          L"SeImpersonatePrivilege"
#define SE_CREATE_GLOBAL_NAME_W                        L"SeCreateGlobalPrivilege"
#define SE_TRUSTED_CREDMAN_ACCESS_NAME_W               L"SeTrustedCredManAccessPrivilege"
#define SE_RELABEL_NAME_W                              L"SeRelabelPrivilege"
#define SE_INC_WORKING_SET_NAME_W                      L"SeIncreaseWorkingSetPrivilege"
#define SE_TIME_ZONE_NAME_W                            L"SeTimeZonePrivilege"
#define SE_CREATE_SYMBOLIC_LINK_NAME_W                 L"SeCreateSymbolicLinkPrivilege"
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME_W    L"SeDelegateSessionUserImpersonatePrivilege"