// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef XIO_ENDPOINT_TLS_MBED_H
#define XIO_ENDPOINT_TLS_MBED_H

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/umock_c_prod.h"

/** @brief	Return the tlsio table of functions.
*
* @param	void.
*
* @return	The tlsio interface (IO_INTERFACE_DESCRIPTION).
*/
MOCKABLE_FUNCTION(, const XIO_ENDPOINT_INTERFACE*, xio_endpoint_tls_mbed_get_interface);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XIO_ENDPOINT_TLS_MBED_H */
