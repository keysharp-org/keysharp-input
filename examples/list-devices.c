#include <keysharp_input/client.h>
#include <stdio.h>

static bool print_device(const ksi_device_info *device, void *context)
{
    (void)context;
    printf("%u: %s, vendor %04x product %04x, unique %s\n",
        device->device_id, device->name, device->vendor, device->product,
        device->unique);
    return true;
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *lease = NULL;
    ksi_connection *observer = NULL;
    ksi_permission_scopes granted = 0u;
    uint64_t generation = 0u;
    int result = 1;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.role = KSI_ROLE_AUTHORIZATION_LEASE;
    options.timeout_ms = 1000u;
    options.requested_scopes = 0u;
    if (ksi_connect(&options, &lease, &info, &error) != KSI_STATUS_OK
        || ksi_devices_authorize(lease, &granted, &error) != KSI_STATUS_OK)
        goto done;

    options.role = KSI_ROLE_OBSERVER_STREAM;
    options.lease_id = info.lease_id;
    if (ksi_connect(&options, &observer, &info, &error) != KSI_STATUS_OK
        || ksi_devices_subscribe(observer, &error) != KSI_STATUS_OK
        || ksi_devices_list(observer, print_device, NULL, &generation, &error)
            != KSI_STATUS_OK) goto done;
    printf("Device generation: %llu\n", (unsigned long long)generation);
    result = 0;
done:
    if (result != 0) fprintf(stderr, "%s\n", error.message);
    ksi_disconnect(observer);
    ksi_disconnect(lease);
    return result;
}
