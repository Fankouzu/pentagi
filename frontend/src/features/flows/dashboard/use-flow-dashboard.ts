import { useQuery } from '@apollo/client';
import { useCallback, useEffect, useMemo, useRef } from 'react';

import { neo4jClient } from './neo4j-client';
import {
    ACCESS_CHAIN_GRAPH_UPDATED_SUBSCRIPTION,
    ACCESS_DETAILS_UPDATED_SUBSCRIPTION,
    ALL_CVES_UPDATED_SUBSCRIPTION,
    ARTIFACTS_UPDATED_SUBSCRIPTION,
    ATTACK_PATH_STATS_UPDATED_SUBSCRIPTION,
    ATTACK_SURFACE_UPDATED_SUBSCRIPTION,
    CREDENTIALS_STATUS_UPDATED_SUBSCRIPTION,
    DASHBOARD_UPDATED_SUBSCRIPTION,
    EXPLOIT_ATTEMPTS_UPDATED_SUBSCRIPTION,
    FULL_ATTACK_CHAIN_UPDATED_SUBSCRIPTION,
    FULL_DASHBOARD_QUERY,
    HOSTS_WITH_SERVICES_UPDATED_SUBSCRIPTION,
    INFRASTRUCTURE_GRAPH_UPDATED_SUBSCRIPTION,
    MAIN_ATTACK_CHAIN_UPDATED_SUBSCRIPTION,
    OPEN_PORTS_UPDATED_SUBSCRIPTION,
    SHORTEST_PATH_GRAPH_UPDATED_SUBSCRIPTION,
    TOOL_EFFECTIVENESS_UPDATED_SUBSCRIPTION,
    TOOL_USAGE_UPDATED_SUBSCRIPTION,
    VULNERABILITY_SEVERITY_UPDATED_SUBSCRIPTION,
} from './neo4j-queries';

// ---------------------------------------------------------------------------
// Types (matching GraphQL schema)
// ---------------------------------------------------------------------------

export interface AccessRecord {
    access: null | string;
    account: null | string;
    host: null | string;
    service: null | string;
    summary: null | string;
}

export interface ArtifactRecord {
    artifact: null | string;
    producedBy: null | string;
    summary: null | string;
}

export interface AttackPathStats {
    accounts: number;
    groupId: string;
    hosts: number;
    ports: number;
    services: number;
    validAccess: number;
    vulnerabilities: number;
}

export interface AttackSurfaceEntity {
    count: number;
    entityType: string;
}

export interface CredentialStatus {
    count: number;
    examples: string[];
    status: string;
}

export interface CveRecord {
    cve: null | string;
    foundOn: null | string;
    source: null | string;
}

export interface ExploitAttempt {
    attemptCount: number;
    status: string;
    vulnerability: null | string;
}

export interface FlowDashboardResult {
    accessChainGraph: GraphData | null;
    accessDetails: AccessRecord[];
    allCves: CveRecord[];
    artifacts: ArtifactRecord[];
    attackPathStats: AttackPathStats | null;
    attackSurface: AttackSurfaceEntity[];
    credentialsStatus: CredentialStatus[];
    dashboard: null | PentestSummary;
    error: null | string;
    exploitAttempts: ExploitAttempt[];
    fullAttackChain: GraphData | null;
    hostsWithServices: HostWithServices[];
    infrastructureGraph: GraphData | null;
    isLoading: boolean;
    mainAttackChain: GraphData | null;
    openPorts: OpenPort[];
    refetch: () => void;
    shortestPathGraph: GraphData | null;
    toolEffectiveness: ToolEffectivenessRecord[];
    toolUsage: ToolUsageRecord[];
    vulnerabilitySeverity: VulnerabilitySeverityRecord[];
}

export interface GraphData {
    data: GraphEdge[];
    groupId: string;
    rows: number;
}

export interface GraphEdge {
    relationType: string;
    source: GraphNode;
    target: GraphNode;
}

export interface GraphNode {
    labels: string[];
    properties: Record<string, unknown>;
}

export interface HostWithServices {
    host: null | string;
    ports: string[];
    services: string[];
}

export interface OpenPort {
    host: null | string;
    port: null | string;
    service: null | string;
}

export type PentestStatus = 'COMPROMISED' | 'SECURE' | 'VULNERABLE';

export interface PentestSummary {
    accounts: number;
    groupId: string;
    hosts: number;
    ports: number;
    services: number;
    status: PentestStatus;
    validAccess: number;
    vulnerabilities: number;
}

export interface ToolEffectivenessRecord {
    discoveries: number;
    discoveryTypes: string[];
    executions: number;
    tool: null | string;
}

export interface ToolUsageRecord {
    executions: number;
    tool: null | string;
}

export interface VulnerabilitySeverityRecord {
    category: string;
    count: number;
    examples: string[];
}

// Full query response
interface FullDashboardData {
    accessChainGraph: GraphData;
    accessDetails: AccessRecord[];
    allCves: CveRecord[];
    artifacts: ArtifactRecord[];
    attackPathStats: AttackPathStats;
    attackSurface: AttackSurfaceEntity[];
    credentialsStatus: CredentialStatus[];
    dashboard: PentestSummary;
    exploitAttempts: ExploitAttempt[];
    fullAttackChain: GraphData;
    hostsWithServices: HostWithServices[];
    infrastructureGraph: GraphData;
    mainAttackChain: GraphData;
    openPorts: OpenPort[];
    shortestPathGraph: GraphData;
    toolEffectiveness: ToolEffectivenessRecord[];
    toolUsage: ToolUsageRecord[];
    vulnerabilitySeverity: VulnerabilitySeverityRecord[];
}

// ---------------------------------------------------------------------------
// Subscription-to-query field mappings for real-time updates
// ---------------------------------------------------------------------------

const SUBSCRIPTION_MAPPINGS: {
    document: ReturnType<typeof import('@apollo/client').gql>;
    queryField: keyof FullDashboardData;
    subscriptionField: string;
}[] = [
    { document: DASHBOARD_UPDATED_SUBSCRIPTION, queryField: 'dashboard', subscriptionField: 'dashboardUpdated' },
    {
        document: ATTACK_SURFACE_UPDATED_SUBSCRIPTION,
        queryField: 'attackSurface',
        subscriptionField: 'attackSurfaceUpdated',
    },
    {
        document: CREDENTIALS_STATUS_UPDATED_SUBSCRIPTION,
        queryField: 'credentialsStatus',
        subscriptionField: 'credentialsStatusUpdated',
    },
    {
        document: ACCESS_DETAILS_UPDATED_SUBSCRIPTION,
        queryField: 'accessDetails',
        subscriptionField: 'accessDetailsUpdated',
    },
    {
        document: HOSTS_WITH_SERVICES_UPDATED_SUBSCRIPTION,
        queryField: 'hostsWithServices',
        subscriptionField: 'hostsWithServicesUpdated',
    },
    { document: OPEN_PORTS_UPDATED_SUBSCRIPTION, queryField: 'openPorts', subscriptionField: 'openPortsUpdated' },
    {
        document: VULNERABILITY_SEVERITY_UPDATED_SUBSCRIPTION,
        queryField: 'vulnerabilitySeverity',
        subscriptionField: 'vulnerabilitySeverityUpdated',
    },
    { document: ALL_CVES_UPDATED_SUBSCRIPTION, queryField: 'allCves', subscriptionField: 'allCvesUpdated' },
    {
        document: EXPLOIT_ATTEMPTS_UPDATED_SUBSCRIPTION,
        queryField: 'exploitAttempts',
        subscriptionField: 'exploitAttemptsUpdated',
    },
    { document: TOOL_USAGE_UPDATED_SUBSCRIPTION, queryField: 'toolUsage', subscriptionField: 'toolUsageUpdated' },
    {
        document: TOOL_EFFECTIVENESS_UPDATED_SUBSCRIPTION,
        queryField: 'toolEffectiveness',
        subscriptionField: 'toolEffectivenessUpdated',
    },
    { document: ARTIFACTS_UPDATED_SUBSCRIPTION, queryField: 'artifacts', subscriptionField: 'artifactsUpdated' },
    {
        document: MAIN_ATTACK_CHAIN_UPDATED_SUBSCRIPTION,
        queryField: 'mainAttackChain',
        subscriptionField: 'mainAttackChainUpdated',
    },
    {
        document: FULL_ATTACK_CHAIN_UPDATED_SUBSCRIPTION,
        queryField: 'fullAttackChain',
        subscriptionField: 'fullAttackChainUpdated',
    },
    {
        document: INFRASTRUCTURE_GRAPH_UPDATED_SUBSCRIPTION,
        queryField: 'infrastructureGraph',
        subscriptionField: 'infrastructureGraphUpdated',
    },
    {
        document: ACCESS_CHAIN_GRAPH_UPDATED_SUBSCRIPTION,
        queryField: 'accessChainGraph',
        subscriptionField: 'accessChainGraphUpdated',
    },
    {
        document: SHORTEST_PATH_GRAPH_UPDATED_SUBSCRIPTION,
        queryField: 'shortestPathGraph',
        subscriptionField: 'shortestPathGraphUpdated',
    },
    {
        document: ATTACK_PATH_STATS_UPDATED_SUBSCRIPTION,
        queryField: 'attackPathStats',
        subscriptionField: 'attackPathStatsUpdated',
    },
];

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useFlowDashboard(groupId: null | string): FlowDashboardResult {
    const skip = !groupId;
    const variables = useMemo(() => ({ groupId: groupId ?? '' }), [groupId]);

    // Main query — fetches all dashboard data at once
    const { data, error, loading, refetch, subscribeToMore } = useQuery<FullDashboardData>(FULL_DASHBOARD_QUERY, {
        client: neo4jClient,
        skip,
        variables,
    });

    // Keep a stable reference to subscribeToMore to avoid re-subscribing on every render.
    // Apollo Client's useQuery returns a new subscribeToMore reference each render,
    // which would cause the useEffect to constantly tear down and recreate subscriptions.
    const subscribeToMoreReference = useRef(subscribeToMore);

    useEffect(() => {
        subscribeToMoreReference.current = subscribeToMore;
    }, [subscribeToMore]);

    // Subscribe to all real-time updates via WebSocket.
    // Each subscription updates its corresponding query field in the Apollo cache.
    useEffect(() => {
        if (skip) {
            return;
        }

        const unsubscribers = SUBSCRIPTION_MAPPINGS.map(({ document, queryField, subscriptionField }) =>
            subscribeToMoreReference.current({
                document,
                updateQuery: (previous, { subscriptionData }) => {
                    const payload = subscriptionData.data as unknown as null | Record<string, unknown>;
                    const updatedValue = payload?.[subscriptionField];

                    if (updatedValue === undefined) {
                        return previous;
                    }

                    return { ...previous, [queryField]: updatedValue } as FullDashboardData;
                },
                variables,
            }),
        );

        return () => unsubscribers.forEach((unsubscribe) => unsubscribe());
    }, [skip, variables]);

    // Refetch on initial mount when groupId becomes available
    useEffect(() => {
        if (!skip) {
            refetch();
        }
    }, [skip, refetch]);

    // Refetch all data on demand
    const handleRefetch = useCallback(() => {
        if (!skip) {
            refetch();
        }
    }, [refetch, skip]);

    return {
        accessChainGraph: data?.accessChainGraph ?? null,
        accessDetails: data?.accessDetails ?? [],
        allCves: data?.allCves ?? [],
        artifacts: data?.artifacts ?? [],
        attackPathStats: data?.attackPathStats ?? null,
        attackSurface: data?.attackSurface ?? [],
        credentialsStatus: data?.credentialsStatus ?? [],
        dashboard: data?.dashboard ?? null,
        error: error ? error.message : null,
        exploitAttempts: data?.exploitAttempts ?? [],
        fullAttackChain: data?.fullAttackChain ?? null,
        hostsWithServices: data?.hostsWithServices ?? [],
        infrastructureGraph: data?.infrastructureGraph ?? null,
        isLoading: loading,
        mainAttackChain: data?.mainAttackChain ?? null,
        openPorts: data?.openPorts ?? [],
        refetch: handleRefetch,
        shortestPathGraph: data?.shortestPathGraph ?? null,
        toolEffectiveness: data?.toolEffectiveness ?? [],
        toolUsage: data?.toolUsage ?? [],
        vulnerabilitySeverity: data?.vulnerabilitySeverity ?? [],
    };
}
