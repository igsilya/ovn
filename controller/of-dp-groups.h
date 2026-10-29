/* Copyright (c) 2026, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OF_DP_GROUPS_H
#define OF_DP_GROUPS_H 1

/* OpenFlow datapath groups.
 * =========================
 *
 * A logical flow that applies to a Logical_DP_Group is normally expanded
 * into one set of OpenFlow flows per local datapath of the group, each
 * matching on the datapath key in MFF_LOG_DATAPATH.
 *
 * The datapath key only uses the low OVN_DP_KEY_BITS bits of the 64-bit
 * MFF_LOG_DATAPATH field.  When OpenFlow datapath groups are enabled, up to
 * OF_DP_GROUPS_MAX_BITS datapath groups get one of the remaining bits
 * assigned.  Every packet entering the ingress or egress pipeline of a
 * datapath passes through OFTABLE_LOG_INGRESS_DP_GROUPS or
 * OFTABLE_LOG_EGRESS_DP_GROUPS, which store the bits of all the groups the
 * datapath belongs to in the upper bits of MFF_LOG_DATAPATH.  A logical flow
 * of a group with a bit assigned is then translated only once into OpenFlow
 * flows that match on that single bit, if its translation doesn't depend on
 * the specific datapath.  Groups without a bit (because more than
 * OF_DP_GROUPS_MAX_BITS groups would be needed) and logical flows whose
 * translation depends on the datapath are expanded as before.
 *
 * All other flows match only on the low OVN_DP_KEY_BITS bits of
 * MFF_LOG_DATAPATH while the feature is enabled. */

#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/hmap.h"
#include "lib/uuidset.h"
#include "ovn/logical-fields.h"

struct hmap;
struct match;
struct ovn_desired_flow_table;
struct ovsdb_idl_index;
struct sbrec_datapath_binding;
struct sbrec_logical_dp_group;
struct sbrec_logical_dp_group_table;

#define OF_DP_GROUPS_MAX_BITS (64 - OVN_DP_KEY_BITS)

/* Global enablement.  Thread safe. */
bool of_dp_groups_set_enabled(bool enabled);
bool of_dp_groups_set_max_bits(unsigned int max_bits);
bool of_dp_groups_enabled(void);

/* Helpers for code that matches on or enters the logical pipelines. */
void ovn_match_set_dp_key(struct match *, uint32_t dp_key);
uint8_t of_dp_groups_ingress_table(void);
uint8_t of_dp_groups_egress_table(void);
void of_dp_groups_add_default_flows(struct ovn_desired_flow_table *,
                                    const struct uuid *);

struct of_dp_groups {
    struct hmap groups;           /* Contains "struct of_dp_group". */
    uint64_t used_bits;           /* Bitmap of assigned bit indexes. */
    struct hmap stamps;           /* Contains "struct of_dp_stamp". */

    /* Logical flows whose OpenFlow flows are currently installed once for
     * their whole datapath group, i.e., match on the group bit. */
    struct uuidset shared_lflows;
};

void of_dp_groups_init(struct of_dp_groups *);
void of_dp_groups_destroy(struct of_dp_groups *);
void of_dp_groups_clear(struct of_dp_groups *);
void of_dp_groups_clear_flows(struct of_dp_groups *);

/* Returns the MFF_LOG_DATAPATH bit assigned to 'ldpg', or 0. */
uint64_t of_dp_groups_get_bit(const struct of_dp_groups *,
                              const struct sbrec_logical_dp_group *);

/* Returns false if the 'is_switch' type of 'ldp' is incompatible with the
 * group the bit was assigned to. */
bool of_dp_groups_dp_compatible(const struct of_dp_groups *,
                                const struct sbrec_logical_dp_group *,
                                bool is_switch);

void of_dp_groups_assign_all(struct of_dp_groups *,
                             const struct sbrec_logical_dp_group_table *,
                             struct ovsdb_idl_index *lflows_by_dp_group,
                             const struct hmap *local_datapaths);
bool of_dp_groups_try_assign(struct of_dp_groups *,
                             const struct sbrec_logical_dp_group *,
                             const struct hmap *local_datapaths);
void of_dp_groups_release(struct of_dp_groups *, const struct uuid *);

void of_dp_groups_sync_stamps(struct of_dp_groups *,
                              const struct sbrec_logical_dp_group_table *,
                              const struct hmap *local_datapaths,
                              struct ovn_desired_flow_table *);

#endif /* controller/of-dp-groups.h */
