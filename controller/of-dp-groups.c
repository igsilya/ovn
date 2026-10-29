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

#include <config.h>

#include "of-dp-groups.h"

#include "lflow.h"
#include "local_data.h"
#include "ofctrl.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "lib/ovn-sb-idl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(of_dp_groups);

/* Priority of the flows that store the group bits of a datapath. */
#define OF_DP_GROUPS_STAMP_PRIO 100

#define OF_DP_GROUPS_BITS_MASK (~OVN_DP_KEY_MASK)

static atomic_bool of_dp_groups_on = false;

/* Number of bits available for datapath groups.  Only used by the main
 * thread. */
static unsigned int of_dp_groups_max_bits = OF_DP_GROUPS_MAX_BITS;

/* A datapath group with an assigned MFF_LOG_DATAPATH bit. */
struct of_dp_group {
    struct hmap_node hmap_node;   /* In of_dp_groups->groups. */
    struct uuid uuid;             /* Logical_DP_Group UUID. */
    unsigned int bit_idx;         /* 0 <= bit_idx < OF_DP_GROUPS_MAX_BITS. */
    bool is_switch;               /* Type of the group's datapaths. */
};

/* Group bits installed for a local datapath. */
struct of_dp_stamp {
    struct hmap_node hmap_node;   /* In of_dp_groups->stamps. */
    struct uuid dp_uuid;          /* Datapath_Binding UUID. */
    uint64_t bits;                /* Bits in MFF_LOG_DATAPATH. */
};

bool
of_dp_groups_set_enabled(bool enabled)
{
    bool old;

    atomic_read_relaxed(&of_dp_groups_on, &old);
    if (old == enabled) {
        return false;
    }
    atomic_store_relaxed(&of_dp_groups_on, enabled);
    VLOG_INFO("OpenFlow datapath groups %s.",
              enabled ? "enabled" : "disabled");
    return true;
}

/* Limits the number of datapath groups that get a bit to 'max_bits'.
 * Returns true if the limit changed. */
bool
of_dp_groups_set_max_bits(unsigned int max_bits)
{
    max_bits = MIN(max_bits, OF_DP_GROUPS_MAX_BITS);
    if (max_bits == of_dp_groups_max_bits) {
        return false;
    }
    of_dp_groups_max_bits = max_bits;
    return true;
}

bool
of_dp_groups_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&of_dp_groups_on, &enabled);
    return enabled;
}

/* Sets 'match' to match on logical datapath 'dp_key'.  If OpenFlow datapath
 * groups are enabled, the group bits in MFF_LOG_DATAPATH are ignored. */
void
ovn_match_set_dp_key(struct match *match, uint32_t dp_key)
{
    if (of_dp_groups_enabled()) {
        match_set_metadata_masked(match, htonll(dp_key),
                                  htonll(OVN_DP_KEY_MASK));
    } else {
        match_set_metadata(match, htonll(dp_key));
    }
}

/* Returns the OpenFlow table to resubmit to for entering the ingress
 * pipeline of the logical datapath in MFF_LOG_DATAPATH. */
uint8_t
of_dp_groups_ingress_table(void)
{
    return of_dp_groups_enabled()
           ? OFTABLE_LOG_INGRESS_DP_GROUPS
           : OFTABLE_LOG_INGRESS_PIPELINE;
}

/* Same as of_dp_groups_ingress_table() for the egress pipeline. */
uint8_t
of_dp_groups_egress_table(void)
{
    return of_dp_groups_enabled()
           ? OFTABLE_LOG_EGRESS_DP_GROUPS
           : OFTABLE_LOG_EGRESS_PIPELINE;
}

static void
put_dp_group_bits(uint64_t bits, uint8_t next_table, struct ofpbuf *ofpacts)
{
    union mf_value value, mask;

    memset(&value, 0, sizeof value);
    memset(&mask, 0, sizeof mask);
    value.be64 = htonll(bits);
    mask.be64 = htonll(OF_DP_GROUPS_BITS_MASK);
    ofpact_put_set_field(ofpacts, mf_from_id(MFF_LOG_DATAPATH),
                         &value, &mask);

    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = next_table;
}

/* Adds the default flows of the datapath group tables: datapaths without
 * group bits get the bits cleared. */
void
of_dp_groups_add_default_flows(struct ovn_desired_flow_table *flow_table,
                               const struct uuid *uuid)
{
    if (!of_dp_groups_enabled()) {
        return;
    }

    struct match match = MATCH_CATCHALL_INITIALIZER;
    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);

    put_dp_group_bits(0, OFTABLE_LOG_INGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_LOG_INGRESS_DP_GROUPS, 0, 0,
                    &match, &ofpacts, uuid);

    ofpbuf_clear(&ofpacts);
    put_dp_group_bits(0, OFTABLE_LOG_EGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_LOG_EGRESS_DP_GROUPS, 0, 0,
                    &match, &ofpacts, uuid);

    ofpbuf_uninit(&ofpacts);
}

void
of_dp_groups_init(struct of_dp_groups *dpgs)
{
    hmap_init(&dpgs->groups);
    hmap_init(&dpgs->stamps);
    uuidset_init(&dpgs->shared_lflows);
    dpgs->used_bits = 0;
}

/* Forgets the state related to installed flows, but keeps the bit
 * assignment.  The caller must make sure the flows are removed, e.g., by
 * clearing the desired flow table. */
void
of_dp_groups_clear_flows(struct of_dp_groups *dpgs)
{
    struct of_dp_stamp *s;
    HMAP_FOR_EACH_POP (s, hmap_node, &dpgs->stamps) {
        free(s);
    }
    uuidset_clear(&dpgs->shared_lflows);
}

/* Forgets all the state, including the bit assignment. */
void
of_dp_groups_clear(struct of_dp_groups *dpgs)
{
    struct of_dp_group *g;
    HMAP_FOR_EACH_POP (g, hmap_node, &dpgs->groups) {
        free(g);
    }
    dpgs->used_bits = 0;
    of_dp_groups_clear_flows(dpgs);
}

void
of_dp_groups_destroy(struct of_dp_groups *dpgs)
{
    of_dp_groups_clear(dpgs);
    hmap_destroy(&dpgs->groups);
    hmap_destroy(&dpgs->stamps);
    uuidset_destroy(&dpgs->shared_lflows);
}

static struct of_dp_group *
of_dp_group_find(const struct of_dp_groups *dpgs, const struct uuid *uuid)
{
    struct of_dp_group *g;
    HMAP_FOR_EACH_WITH_HASH (g, hmap_node, uuid_hash(uuid), &dpgs->groups) {
        if (uuid_equals(&g->uuid, uuid)) {
            return g;
        }
    }
    return NULL;
}

static uint64_t
of_dp_group_bit(const struct of_dp_group *g)
{
    return UINT64_C(1) << (OVN_DP_KEY_BITS + g->bit_idx);
}

uint64_t
of_dp_groups_get_bit(const struct of_dp_groups *dpgs,
                     const struct sbrec_logical_dp_group *ldpg)
{
    if (!ldpg || hmap_is_empty(&dpgs->groups)) {
        return 0;
    }
    const struct of_dp_group *g = of_dp_group_find(dpgs, &ldpg->header_.uuid);
    return g ? of_dp_group_bit(g) : 0;
}

bool
of_dp_groups_dp_compatible(const struct of_dp_groups *dpgs,
                           const struct sbrec_logical_dp_group *ldpg,
                           bool is_switch)
{
    const struct of_dp_group *g = of_dp_group_find(dpgs, &ldpg->header_.uuid);
    return !g || g->is_switch == is_switch;
}

static const struct local_datapath *
get_local_dp(const struct hmap *local_datapaths,
             const struct sbrec_datapath_binding *dp)
{
    const struct local_datapath *ldp =
        get_local_datapath(local_datapaths, dp->tunnel_key);
    return ldp && ldp->datapath == dp ? ldp : NULL;
}

/* A group is worth a bit if it has at least two local datapaths.  All local
 * datapaths of a group must be of the same type, because the translation of
 * some actions depends on it. */
static bool
of_dp_group_is_eligible(const struct sbrec_logical_dp_group *ldpg,
                        const struct hmap *local_datapaths,
                        size_t *n_localp, bool *is_switchp)
{
    size_t n_local = 0;
    bool is_switch = false;

    for (size_t i = 0; i < ldpg->n_datapaths; i++) {
        const struct local_datapath *ldp =
            get_local_dp(local_datapaths, ldpg->datapaths[i]);
        if (!ldp) {
            continue;
        }
        if (n_local && ldp->is_switch != is_switch) {
            return false;
        }
        is_switch = ldp->is_switch;
        n_local++;
    }

    *n_localp = n_local;
    *is_switchp = is_switch;
    return n_local >= 2;
}

static bool
of_dp_group_add(struct of_dp_groups *dpgs, const struct uuid *uuid,
                bool is_switch)
{
    BUILD_ASSERT_DECL(OF_DP_GROUPS_MAX_BITS < 64);
    uint64_t free_bits = (~dpgs->used_bits
                          & ((UINT64_C(1) << of_dp_groups_max_bits) - 1));
    if (!free_bits) {
        return false;
    }

    struct of_dp_group *g = xmalloc(sizeof *g);
    g->uuid = *uuid;
    g->bit_idx = rightmost_1bit_idx(free_bits);
    g->is_switch = is_switch;
    dpgs->used_bits |= UINT64_C(1) << g->bit_idx;
    hmap_insert(&dpgs->groups, &g->hmap_node, uuid_hash(uuid));
    VLOG_DBG("Assigned datapath group bit %u to "UUID_FMT,
             g->bit_idx, UUID_ARGS(uuid));
    return true;
}

struct of_dp_group_candidate {
    const struct sbrec_logical_dp_group *ldpg;
    uint64_t score;
    bool is_switch;
};

static int
of_dp_group_candidate_cmp(const void *a_, const void *b_)
{
    const struct of_dp_group_candidate *a = a_;
    const struct of_dp_group_candidate *b = b_;

    if (a->score != b->score) {
        return a->score > b->score ? -1 : 1;
    }
    return uuid_compare_3way(&a->ldpg->header_.uuid, &b->ldpg->header_.uuid);
}

static void
of_dp_group_remove(struct of_dp_groups *dpgs, struct of_dp_group *g)
{
    VLOG_DBG("Released datapath group bit %u of "UUID_FMT,
             g->bit_idx, UUID_ARGS(&g->uuid));
    dpgs->used_bits &= ~(UINT64_C(1) << g->bit_idx);
    hmap_remove(&dpgs->groups, &g->hmap_node);
    free(g);
}

/* Updates the bit assignment after a full recompute.  Groups keep their bits
 * as long as they are still eligible, so that a recompute doesn't change
 * the OpenFlow flows needlessly.  The available bits are assigned to the
 * remaining groups that save the most OpenFlow flows. */
void
of_dp_groups_assign_all(struct of_dp_groups *dpgs,
                        const struct sbrec_logical_dp_group_table *table,
                        struct ovsdb_idl_index *lflows_by_dp_group,
                        const struct hmap *local_datapaths)
{
    if (!of_dp_groups_enabled()) {
        of_dp_groups_clear(dpgs);
        return;
    }

    struct of_dp_group *g;
    HMAP_FOR_EACH_SAFE (g, hmap_node, &dpgs->groups) {
        const struct sbrec_logical_dp_group *ldpg =
            sbrec_logical_dp_group_table_get_for_uuid(table, &g->uuid);
        size_t n_local;
        bool is_switch;

        if (!ldpg || g->bit_idx >= of_dp_groups_max_bits
            || !of_dp_group_is_eligible(ldpg, local_datapaths,
                                        &n_local, &is_switch)
            || is_switch != g->is_switch) {
            of_dp_group_remove(dpgs, g);
        }
    }

    struct of_dp_group_candidate *cands = NULL;
    size_t n_cands = 0, allocated_cands = 0;
    struct sbrec_logical_flow *lf_row =
        sbrec_logical_flow_index_init_row(lflows_by_dp_group);

    const struct sbrec_logical_dp_group *ldpg;
    SBREC_LOGICAL_DP_GROUP_TABLE_FOR_EACH (ldpg, table) {
        size_t n_local;
        bool is_switch;

        if (of_dp_group_find(dpgs, &ldpg->header_.uuid)
            || !of_dp_group_is_eligible(ldpg, local_datapaths,
                                        &n_local, &is_switch)) {
            continue;
        }

        size_t n_lflows = 0;
        const struct sbrec_logical_flow *lflow OVS_UNUSED;
        sbrec_logical_flow_index_set_logical_dp_group(lf_row, ldpg);
        SBREC_LOGICAL_FLOW_FOR_EACH_EQUAL (lflow, lf_row,
                                           lflows_by_dp_group) {
            n_lflows++;
        }
        if (!n_lflows) {
            continue;
        }

        if (n_cands >= allocated_cands) {
            cands = x2nrealloc(cands, &allocated_cands, sizeof *cands);
        }
        cands[n_cands++] = (struct of_dp_group_candidate) {
            .ldpg = ldpg,
            .score = (uint64_t) (n_local - 1) * n_lflows,
            .is_switch = is_switch,
        };
    }
    sbrec_logical_flow_index_destroy_row(lf_row);

    qsort(cands, n_cands, sizeof *cands, of_dp_group_candidate_cmp);
    for (size_t i = 0; i < n_cands; i++) {
        if (!of_dp_group_add(dpgs, &cands[i].ldpg->header_.uuid,
                             cands[i].is_switch)) {
            VLOG_DBG("Out of datapath group bits, %"PRIuSIZE" groups are "
                     "expanded", n_cands - i);
            break;
        }
    }
    free(cands);
}

/* Assigns a free bit to 'ldpg', if it doesn't have one yet and it's worth
 * it.  Returns true if a new bit was assigned. */
bool
of_dp_groups_try_assign(struct of_dp_groups *dpgs,
                        const struct sbrec_logical_dp_group *ldpg,
                        const struct hmap *local_datapaths)
{
    size_t n_local;
    bool is_switch;

    if (!of_dp_groups_enabled()
        || of_dp_group_find(dpgs, &ldpg->header_.uuid)
        || !of_dp_group_is_eligible(ldpg, local_datapaths,
                                    &n_local, &is_switch)) {
        return false;
    }
    return of_dp_group_add(dpgs, &ldpg->header_.uuid, is_switch);
}

void
of_dp_groups_release(struct of_dp_groups *dpgs, const struct uuid *uuid)
{
    struct of_dp_group *g = of_dp_group_find(dpgs, uuid);
    if (g) {
        of_dp_group_remove(dpgs, g);
    }
}

static struct of_dp_stamp *
of_dp_stamp_find(const struct hmap *stamps, const struct uuid *dp_uuid)
{
    struct of_dp_stamp *s;
    HMAP_FOR_EACH_WITH_HASH (s, hmap_node, uuid_hash(dp_uuid), stamps) {
        if (uuid_equals(&s->dp_uuid, dp_uuid)) {
            return s;
        }
    }
    return NULL;
}

static void
of_dp_stamp_add_flows(const struct sbrec_datapath_binding *dp, uint64_t bits,
                      struct ovn_desired_flow_table *flow_table)
{
    struct match match = MATCH_CATCHALL_INITIALIZER;
    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);

    match_set_metadata_masked(&match, htonll(dp->tunnel_key),
                              htonll(OVN_DP_KEY_MASK));

    put_dp_group_bits(bits, OFTABLE_LOG_INGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_LOG_INGRESS_DP_GROUPS,
                    OF_DP_GROUPS_STAMP_PRIO, dp->header_.uuid.parts[0],
                    &match, &ofpacts, &dp->header_.uuid);

    ofpbuf_clear(&ofpacts);
    put_dp_group_bits(bits, OFTABLE_LOG_EGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_LOG_EGRESS_DP_GROUPS,
                    OF_DP_GROUPS_STAMP_PRIO, dp->header_.uuid.parts[0],
                    &match, &ofpacts, &dp->header_.uuid);

    ofpbuf_uninit(&ofpacts);
}

struct of_dp_stamp_want {
    struct hmap_node hmap_node;
    const struct sbrec_datapath_binding *dp;
    uint64_t bits;
};

/* Brings the flows that store the group bits of each local datapath in
 * sync with the current bit assignment and group membership. */
void
of_dp_groups_sync_stamps(struct of_dp_groups *dpgs,
                         const struct sbrec_logical_dp_group_table *table,
                         const struct hmap *local_datapaths,
                         struct ovn_desired_flow_table *flow_table)
{
    struct hmap want = HMAP_INITIALIZER(&want);
    struct of_dp_stamp_want *w;

    const struct of_dp_group *g;
    HMAP_FOR_EACH (g, hmap_node, &dpgs->groups) {
        const struct sbrec_logical_dp_group *ldpg =
            sbrec_logical_dp_group_table_get_for_uuid(table, &g->uuid);
        if (!ldpg) {
            continue;
        }
        for (size_t i = 0; i < ldpg->n_datapaths; i++) {
            const struct sbrec_datapath_binding *dp = ldpg->datapaths[i];
            const struct local_datapath *ldp =
                get_local_dp(local_datapaths, dp);
            if (!ldp || ldp->is_switch != g->is_switch) {
                continue;
            }

            uint32_t hash = uuid_hash(&dp->header_.uuid);
            struct of_dp_stamp_want *found = NULL;
            HMAP_FOR_EACH_WITH_HASH (w, hmap_node, hash, &want) {
                if (w->dp == dp) {
                    found = w;
                    break;
                }
            }
            if (!found) {
                found = xzalloc(sizeof *found);
                found->dp = dp;
                hmap_insert(&want, &found->hmap_node, hash);
            }
            found->bits |= of_dp_group_bit(g);
        }
    }

    struct of_dp_stamp *s;
    HMAP_FOR_EACH_SAFE (s, hmap_node, &dpgs->stamps) {
        bool keep = false;
        HMAP_FOR_EACH_WITH_HASH (w, hmap_node, s->hmap_node.hash, &want) {
            if (uuid_equals(&w->dp->header_.uuid, &s->dp_uuid)) {
                keep = w->bits == s->bits;
                break;
            }
        }
        if (!keep) {
            ofctrl_remove_flows(flow_table, &s->dp_uuid);
            hmap_remove(&dpgs->stamps, &s->hmap_node);
            free(s);
        }
    }

    HMAP_FOR_EACH_POP (w, hmap_node, &want) {
        if (!of_dp_stamp_find(&dpgs->stamps, &w->dp->header_.uuid)) {
            of_dp_stamp_add_flows(w->dp, w->bits, flow_table);
            s = xmalloc(sizeof *s);
            s->dp_uuid = w->dp->header_.uuid;
            s->bits = w->bits;
            hmap_insert(&dpgs->stamps, &s->hmap_node,
                        uuid_hash(&s->dp_uuid));
        }
        free(w);
    }
    hmap_destroy(&want);
}
