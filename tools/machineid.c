/* Prints this machine's fingerprint and name as the license server sees them.
 * Compare with the .NET SDK's DeviceId output to confirm parity. */
#include <stdio.h>

#include "hymma/hlm.h"

int main(void)
{
#if defined(_WIN32)
    char id[HLM_MAX_MACHINE_ID], name[HLM_MAX_NAME];
    int r = hlm_machine_id_win(id, sizeof(id));
    if (r != HLM_OK) {
        printf("machine id unavailable: %s\n", hlm_err_str(r));
        return 1;
    }
    if (hlm_machine_name_win(name, sizeof(name)) != HLM_OK) name[0] = '\0';
    printf("MachineId:   %s\nMachineName: %s\n", id, name);
    return 0;
#else
    printf("built-in fingerprint sources are Windows-only; on other platforms\n"
           "feed your own components to hlm_fingerprint().\n");
    return 1;
#endif
}
