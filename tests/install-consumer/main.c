#include <keysharp_input/client.h>

int main(void)
{
    return ksi_client_abi_major() == KSI_CLIENT_ABI_MAJOR
            && ksi_client_abi_minor() >= KSI_CLIENT_ABI_MINOR
        ? 0 : 1;
}
