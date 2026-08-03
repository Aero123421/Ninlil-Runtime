#include "fabric_private_select.h"

static int dig_eq(const uint8_t a[32], const uint8_t b[32])
{
    return ninlil_fabric_private_memeq(a, b, 32u);
}

static int id_eq(const uint8_t a[16], const uint8_t b[16])
{
    return ninlil_fabric_private_memeq(a, b, 16u);
}

static const char *first_reason(
    const ninlil_fabric_private_select_eval_t *evaluated,
    uint32_t count)
{
    uint32_t i;
    for (i = 0u; i < count; ++i) {
        if (evaluated[i].primary_rejection != NULL) {
            return evaluated[i].primary_rejection;
        }
    }
    return NULL;
}

static int compare_sort(
    const ninlil_fabric_private_select_eval_t *a,
    const ninlil_fabric_private_select_eval_t *b)
{
    if (a->sort_rank != b->sort_rank) {
        return a->sort_rank < b->sort_rank ? -1 : 1;
    }
    if (a->sort_latency != b->sort_latency) {
        return a->sort_latency < b->sort_latency ? -1 : 1;
    }
    if (a->sort_cost != b->sort_cost) {
        return a->sort_cost < b->sort_cost ? -1 : 1;
    }
    return ninlil_fabric_private_id_cmp(a->instance_id, b->instance_id);
}

void ninlil_fabric_private_select(
    const ninlil_fabric_private_select_snapshot_t *snapshot,
    ninlil_fabric_private_select_result_t *out)
{
    const ninlil_fabric_private_select_query_t *q;
    const ninlil_fabric_private_select_policy_t *policy;
    uint32_t i;
    uint32_t match_count;
    uint32_t match_index;
    ninlil_fabric_private_select_eval_t eligible[8];
    uint32_t eligible_count;
    const char *endpoint_selector_name;
    uint8_t endpoint_runtime[16];

    if (out == NULL) {
        return;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    if (snapshot == NULL) {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_CORRUPT;
        out->primary_rejection = "INVALID_SNAPSHOT";
        return;
    }
    q = &snapshot->query;
    if (snapshot->outer_available != 1u) {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE;
        out->primary_rejection = "META_OUTER_UNAVAILABLE";
        return;
    }

    for (i = 0u; i < snapshot->policy_count; ++i) {
        const ninlil_fabric_private_select_policy_t *p =
            &snapshot->policies[i];
        uint32_t c;
        if (p->revision_chain_len == 0u
            || p->revision_chain[p->revision_chain_len - 1u] != p->revision) {
            out->resolution = NINLIL_FABRIC_PRIVATE_SEL_CORRUPT;
            out->primary_rejection = "POLICY_REVISION_GAP";
            return;
        }
        for (c = 1u; c < p->revision_chain_len; ++c) {
            if (p->revision_chain[c] != p->revision_chain[c - 1u] + 1u) {
                out->resolution = NINLIL_FABRIC_PRIVATE_SEL_CORRUPT;
                out->primary_rejection = "POLICY_REVISION_GAP";
                return;
            }
        }
    }

    /*
     * ADR-0017: resolver uses only the maximum revision per policy ID.
     * Old retained revisions in the snapshot must not count as current.
     */
    match_count = 0u;
    match_index = 0u;
    for (i = 0u; i < snapshot->policy_count; ++i) {
        const ninlil_fabric_private_select_policy_t *p =
            &snapshot->policies[i];
        uint32_t j;
        int is_max = 1;
        if (!dig_eq(p->service_identity_digest, q->service_identity_digest)
            || p->family != q->family || p->direction != q->direction
            || p->traffic_class != q->traffic_class) {
            continue;
        }
        for (j = 0u; j < snapshot->policy_count; ++j) {
            const ninlil_fabric_private_select_policy_t *o =
                &snapshot->policies[j];
            if (j == i) {
                continue;
            }
            if (id_eq(o->policy_id, p->policy_id)
                && o->revision > p->revision) {
                is_max = 0;
                break;
            }
        }
        if (is_max == 0) {
            continue;
        }
        if (match_count == 0u) {
            match_index = i;
        }
        match_count++;
    }
    if (match_count == 0u) {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_NO_POLICY;
        out->primary_rejection = "POLICY_NO_MATCH";
        return;
    }
    if (match_count != 1u) {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_CORRUPT;
        out->primary_rejection = "POLICY_AMBIGUOUS";
        return;
    }
    policy = &snapshot->policies[match_index];

    if (policy->scope_selector == 1u) {
        endpoint_selector_name = "SOURCE_RUNTIME";
        ninlil_fabric_private_id_copy(endpoint_runtime, q->source_runtime_id);
    } else if (policy->scope_selector == 2u) {
        endpoint_selector_name = "TARGET_RUNTIME";
        ninlil_fabric_private_id_copy(endpoint_runtime, q->target_runtime_id);
    } else {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_CORRUPT;
        out->primary_rejection = "SCOPE_SELECTOR_UNKNOWN";
        return;
    }
    (void)endpoint_selector_name;

    eligible_count = 0u;
    for (i = 0u; i < policy->candidate_count && i < 8u; ++i) {
        const ninlil_fabric_private_policy_candidate_t *cand =
            &policy->candidates[i];
        ninlil_fabric_private_select_eval_t *ev;
        const ninlil_fabric_private_select_registry_row_t *reg;
        const ninlil_fabric_private_select_authority_row_t *auth;
        uint32_t r;
        uint32_t a;
        uint32_t reg_matches;
        uint32_t auth_matches;
        uint32_t reg_index;
        uint32_t auth_index;
        const char *reason;

        if (out->evaluated_count >= 8u) {
            break;
        }
        ev = &out->evaluated[out->evaluated_count];
        out->evaluated_count++;
        ninlil_fabric_private_memzero(ev, sizeof(*ev));
        ninlil_fabric_private_id_copy(ev->instance_id, cand->instance_id);
        reason = NULL;
        reg = NULL;
        auth = NULL;
        reg_matches = 0u;
        reg_index = 0u;
        for (r = 0u; r < snapshot->registry_count; ++r) {
            if (id_eq(snapshot->registry[r].instance_id, cand->instance_id)) {
                if (reg_matches == 0u) {
                    reg_index = r;
                }
                reg_matches++;
            }
        }
        if (reg_matches == 0u) {
            reason = "REGISTRY_JOIN_MISSING";
        } else if (reg_matches != 1u) {
            reason = "REGISTRY_JOIN_AMBIGUOUS";
        } else {
            reg = &snapshot->registry[reg_index];
        }

        auth_matches = 0u;
        auth_index = 0u;
        for (a = 0u; a < snapshot->authority_count; ++a) {
            const ninlil_fabric_private_select_authority_row_t *row =
                &snapshot->authorities[a];
            if (dig_eq(row->service_identity_digest, q->service_identity_digest)
                && row->family == q->family && row->direction == q->direction
                && row->traffic_class == q->traffic_class
                && row->scope_selector == policy->scope_selector
                && id_eq(row->endpoint_runtime_id, endpoint_runtime)
                && id_eq(row->target_runtime_id, q->target_runtime_id)
                && id_eq(row->target_application_id, q->target_application_id)
                && id_eq(row->policy_id, policy->policy_id)
                && row->policy_revision == policy->revision
                && dig_eq(row->policy_digest, policy->canonical_digest)) {
                if (auth_matches == 0u) {
                    auth_index = a;
                }
                auth_matches++;
            }
        }
        if (reason == NULL) {
            if (auth_matches == 0u) {
                reason = "AUTHORITY_JOIN_MISSING";
            } else if (auth_matches != 1u) {
                reason = "AUTHORITY_JOIN_AMBIGUOUS";
            } else {
                auth = &snapshot->authorities[auth_index];
            }
        }

        if (reason == NULL && reg != NULL) {
            uint32_t required_caps;
            uint32_t required_sec;
            uint32_t used_units;
            uint32_t t;

            if (reg->lifecycle != NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE) {
                reason = "LIFECYCLE_DRAINING";
            } else if ((reg->direction_mask & 1u) == 0u) {
                reason = "DIRECTION_MISMATCH";
            } else if (q->packet_bytes < NINLIL_FABRIC_NFL1_STRUCTURAL_MIN) {
                reason = "STRUCTURAL_LENGTH_FLOOR";
            } else if (q->packet_bytes > NINLIL_FABRIC_NFL1_STRUCTURAL_MAX) {
                reason = "STRUCTURAL_LENGTH_CEILING";
            } else if (q->packet_bytes < policy->minimum_packet_bytes) {
                reason = "PACKET_MINIMUM";
            } else if (q->packet_bytes > reg->maximum_packet_bytes) {
                reason = "PACKET_MTU";
            } else if (q->transfer_bytes > reg->maximum_transfer_bytes) {
                reason = "TRANSFER_MTU";
            } else if (reg->latency_class > policy->maximum_latency_class) {
                reason = "LATENCY_CLASS";
            } else if (reg->cost_class > policy->maximum_cost_class) {
                reason = "COST_CLASS";
            } else if (q->now_ms > q->deadline_ms
                || (q->deadline_ms - q->now_ms) < policy->deadline_guard_ms) {
                /* now > deadline must not underflow unsigned subtraction. */
                reason = "DEADLINE_GUARD";
            } else if (!id_eq(
                           q->deadline_clock_epoch_id,
                           q->admission_clock_epoch_id)
                || !id_eq(
                       q->deadline_clock_epoch_id,
                       q->availability_clock_epoch_id)) {
                reason = "RETRY_LIFETIME_CLOCK_EPOCH";
            } else {
                used_units = 0u;
                for (t = 0u; t < snapshot->active_attempt_count; ++t) {
                    const ninlil_fabric_private_select_active_attempt_t *at =
                        &snapshot->active_attempts[t];
                    if (id_eq(at->instance_id, cand->instance_id)
                        && (at->state
                                == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED
                            || at->state
                                == NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED)) {
                        used_units =
                            (uint32_t)(used_units + at->reservation_units);
                    }
                }
                if (used_units + cand->reservation_units
                    > reg->reservation_capacity) {
                    reason = "RESERVATION_CAPACITY";
                }
            }

            if (reason == NULL) {
                required_caps = policy->required_capability_flags
                    | q->required_capability_flags;
                if ((reg->capability_flags & required_caps) != required_caps) {
                    reason = "CAPABILITY_MISSING";
                } else if (q->requires_sleep_compatible != 0u
                    && (reg->capability_flags & 1u) == 0u) {
                    reason = "ENERGY_SLEEP_CAPABILITY_MISSING";
                } else {
                    required_sec = policy->required_security_flags
                        | q->required_security_flags;
                    if ((reg->security_capability_flags & required_sec)
                        != required_sec) {
                        reason = "SECURITY_MISSING";
                    } else if (q->requires_custody != 0u
                        && (reg->link_kind == 2u
                            || (reg->capability_flags & 0x20u) == 0u)) {
                        /* ADR-0018: Wi-Fi is never custody-capable. */
                        reason = "CUSTODY_MISSING";
                    } else if (q->requires_evidence != 0u
                        && (reg->capability_flags & 0x40u) == 0u) {
                        reason = "EVIDENCE_MISSING";
                    } else if (reg->peer_nfl1_version != 1u
                        || (reg->peer_fabric_capability_flags & 1u) == 0u) {
                        reason = "PEER_NFL1";
                    } else if (ninlil_fabric_private_id_is_zero(
                                   reg->authenticated_peer_runtime_id)) {
                        reason = "AUTHENTICATED_PEER_ABSENT";
                    } else if (
                        !ninlil_fabric_private_id_is_zero(
                            q->authenticated_peer_runtime_id)
                        && !id_eq(
                               reg->authenticated_peer_runtime_id,
                               q->authenticated_peer_runtime_id)) {
                        /*
                         * Caller-supplied peer expectation (non-zero) must
                         * match. Zero query = no enumeration-order seed;
                         * each candidate is judged on its own peer pin.
                         */
                        reason = "AUTHENTICATED_PEER_MISMATCH";
                    } else if (ninlil_fabric_private_id_is_zero(
                                   reg->attachment_authority_id)
                        || ninlil_fabric_private_is_zero(
                               reg->attachment_binding_digest, 32u)) {
                        reason = "ATTACHMENT_ABSENT";
                    } else if (
                        !ninlil_fabric_private_id_is_zero(
                            q->attachment_authority_id)
                        && !id_eq(
                               reg->attachment_authority_id,
                               q->attachment_authority_id)) {
                        reason = "ATTACHMENT_AUTHORITY_MISMATCH";
                    } else if (
                        !ninlil_fabric_private_is_zero(
                            q->attachment_binding_digest, 32u)
                        && !dig_eq(
                               reg->attachment_binding_digest,
                               q->attachment_binding_digest)) {
                        reason = "ATTACHMENT_BINDING_MISMATCH";
                    } else if (!id_eq(
                                   reg->attestation_clock_epoch_id,
                                   q->attestation_clock_epoch_id)) {
                        reason = "ATTESTATION_EPOCH";
                    } else if (q->now_ms >= reg->attestation_expires_at_ms) {
                        reason = "ATTESTATION_EXPIRED";
                    } else if (!id_eq(
                                   reg->availability_clock_epoch_id,
                                   q->availability_clock_epoch_id)) {
                        reason = "AVAILABILITY_EPOCH";
                    } else if (reg->availability_state != 1u) {
                        reason = "AVAILABILITY_STATE";
                    } else if (q->now_ms >= reg->availability_expires_at_ms) {
                        reason = "AVAILABILITY_EXPIRED";
                    }
                }
            }

            if (reason == NULL && auth != NULL) {
                if (policy->authority_mode == 1u
                    && auth->authority_state != 1u) {
                    reason = "BOUND_REQUIRED_ABSENT";
                } else if (auth->authority_state == 1u) {
                    if (!id_eq(
                            auth->authority_clock_epoch_id,
                            q->authority_clock_epoch_id)) {
                        reason = "AUTHORITY_CLOCK_EPOCH";
                    } else if (q->now_ms >= auth->lease_expires_at_ms) {
                        reason = "AUTHORITY_LEASE_EXPIRED";
                    }
                }
            }

            if (reason == NULL && reg->link_kind == 4u) {
                if (q->rf_permit_valid == 0u) {
                    reason = "RF_PERMIT";
                } else if (q->rf_mapping_accepted == 0u) {
                    reason = "RF_MAPPING_UNSUPPORTED";
                } else if (reg->rf_mapping_approved == 0u) {
                    reason = "RF_PATH_NOT_APPROVED";
                }
            }

            if (reason == NULL) {
                ev->eligible = 1u;
                ev->sort_rank = cand->rank;
                ev->sort_latency = reg->latency_class;
                ev->sort_cost = reg->cost_class;
            }
        }
        ev->primary_rejection = reason;
        if (ev->eligible != 0u && eligible_count < 8u) {
            eligible[eligible_count] = *ev;
            eligible_count++;
        }
    }

    if (eligible_count > 0u) {
        uint32_t j;
        for (i = 0u; i + 1u < eligible_count; ++i) {
            for (j = i + 1u; j < eligible_count; ++j) {
                if (compare_sort(&eligible[j], &eligible[i]) < 0) {
                    ninlil_fabric_private_select_eval_t tmp = eligible[i];
                    eligible[i] = eligible[j];
                    eligible[j] = tmp;
                }
            }
        }
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_SELECTED;
        out->has_selection = 1u;
        ninlil_fabric_private_id_copy(
            out->selected_instance_id, eligible[0].instance_id);
        out->primary_rejection = NULL;
    } else {
        out->resolution = NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE;
        out->primary_rejection =
            first_reason(out->evaluated, out->evaluated_count);
    }
}
