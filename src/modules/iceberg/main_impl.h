/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_MAIN_H
#define SECP256K1_MODULE_ICEBERG_MAIN_H

/* Layers, bottom up. Each one may use those above it in this list and nothing
 * below. That ordering is also the constant-time story: vpss sees only
 * participant indices and published points and is variable time throughout,
 * while scalar_poly has secret values passed through it and keeps them away
 * from its inversions, as the note at the top of scalar_poly.h sets out. Seed
 * material reaches rss_eval and the scalars keygen and session derive from it,
 * which is where the clearing discipline lives. */
#include "scalar_poly_impl.h"
#include "rss_impl.h"
#include "vpss_impl.h"
#include "keygen_impl.h"
#include "session_impl.h"

#endif
