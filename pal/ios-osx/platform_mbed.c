// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/xio_impl.h"
#include "xio_endpoint_config_tls.h"

#include <stdlib.h>

#include "xio_endpoint_tls_mbed.h"

int platform_init(void)
{
    return 0;
}

const IO_INTERFACE_DESCRIPTION* platform_get_default_tlsio(void)
{
    return tlsio_basic_get_interface_description(xio_endpoint_tls_mbed_get_interface(), TLSIO_OPTION_BIT_TRUSTED_CERTS);
}

STRING_HANDLE platform_get_platform_info(void)
{
    STRING_HANDLE result = STRING_construct_sprintf("mbed tls");

    return result;
}

void platform_deinit(void)
{
}
