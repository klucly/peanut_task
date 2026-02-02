use crate::core::base_types::{Address, Token, TokenAmount};
use std::collections::HashMap;
use std::collections::HashSet;
use thiserror::Error;

use super::uniswap_v2_pair::{UniswapV2Pair, UniswapV2PairError};

const GWEI_PER_WEI: u128 = 1_000_000_000;

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Pair(#[from] UniswapV2PairError),
    #[error("Invalid route: {0}")]
    InvalidRoute(String),
}

/// Represents a swap route through one or more pools.
#[derive(Debug, Clone)]
pub struct Route {
    pub pools: Vec<UniswapV2Pair>,
    /// token_in -> intermediate... -> token_out
    pub path: Vec<Token>,
}

impl Route {
    /// Creates a new Route, validating that path and pools are consistent.
    pub fn new(
        pools: Vec<UniswapV2Pair>,
        path: Vec<Token>,
    ) -> Result<Self, RouteError> {
        if pools.is_empty() || path.len() < 2 {
            return Err(RouteError::InvalidRoute(
                "Route must have at least one pool and path of length >= 2".to_string(),
            ));
        }
        if path.len() != pools.len() + 1 {
            return Err(RouteError::InvalidRoute(format!(
                "path.len() ({}) must equal pools.len() + 1 ({})",
                path.len(),
                pools.len() + 1
            )));
        }
        for (i, pool) in pools.iter().enumerate() {
            let a = &path[i];
            let b = &path[i + 1];
            let t0 = &pool.token0.token;
            let t1 = &pool.token1.token;
            let valid = (a == t0 && b == t1) || (a == t1 && b == t0);
            if !valid {
                return Err(RouteError::InvalidRoute(format!(
                    "path[{}..{}] does not match pool {} tokens",
                    i,
                    i + 2,
                    i
                )));
            }
        }
        Ok(Self { pools, path })
    }

    pub fn num_hops(&self) -> usize {
        self.pools.len()
    }

    fn simulate(&self, amount_in: u128) -> Result<Vec<u128>, RouteError> {
        let mut amounts = Vec::with_capacity(self.pools.len() + 1);
        amounts.push(amount_in);

        let mut current_amount = amount_in;
        let mut current_token = &self.path[0];

        for (i, pool) in self.pools.iter().enumerate() {
            let amount_in_ta = TokenAmount::new(current_amount, current_token.clone());
            let amount_out = pool.get_amount_out(&amount_in_ta)?;
            current_amount = amount_out.raw;
            current_token = &self.path[i + 1];
            amounts.push(current_amount);
        }

        Ok(amounts)
    }

    /// Simulate full route, return final output.
    pub fn get_output(&self, amount_in: u128) -> Result<TokenAmount, RouteError> {
        let amounts = self.simulate(amount_in)?;
        let last_amount = amounts.last().copied().unwrap_or(0);
        let token_out = self.path.last().cloned().ok_or_else(|| {
            RouteError::InvalidRoute("path is empty".to_string())
        })?;
        Ok(TokenAmount::new(last_amount, token_out))
    }

    /// Return amount at each step: [input, after_hop1, after_hop2, ...]
    pub fn get_intermediate_amounts(&self, amount_in: u128) -> Result<Vec<u128>, RouteError> {
        self.simulate(amount_in)
    }

    /// Estimate gas: ~150k base + ~100k per hop.
    pub fn estimate_gas(&self) -> u64 {
        150_000 + (self.num_hops() as u64) * 100_000
    }

    /// Resolve path tokens to contract addresses using pool token metadata.
    pub fn path_addresses(&self) -> Vec<Address> {
        let mut addrs = Vec::with_capacity(self.path.len());
        for (i, token) in self.path.iter().enumerate() {
            let pool_idx = i.min(self.pools.len().saturating_sub(1));
            let pool = &self.pools[pool_idx];
            let addr = if token == &pool.token0.token {
                pool.token0.address.clone()
            } else {
                pool.token1.address.clone()
            };
            addrs.push(addr);
        }
        addrs
    }
}

/// Finds optimal routes between tokens.
pub struct RouteFinder {
    pub pools: Vec<UniswapV2Pair>,
    graph: HashMap<Token, Vec<(usize, Token)>>,
}

impl RouteFinder {
    pub fn new(pools: Vec<UniswapV2Pair>) -> Self {
        let graph = Self::build_graph(&pools);
        Self { pools, graph }
    }

    fn build_graph(pools: &[UniswapV2Pair]) -> HashMap<Token, Vec<(usize, Token)>> {
        let mut graph: HashMap<Token, Vec<(usize, Token)>> = HashMap::new();
        for (i, pool) in pools.iter().enumerate() {
            let t0 = pool.token0.token.clone();
            let t1 = pool.token1.token.clone();
            graph
                .entry(t0.clone())
                .or_default()
                .push((i, t1.clone()));
            graph
                .entry(t1)
                .or_default()
                .push((i, t0));
        }
        graph
    }

    /// Find all possible routes up to max_hops using bidirectional (meet-in-the-middle) search.
    pub fn find_all_routes(
        &self,
        token_in: &Token,
        token_out: &Token,
        max_hops: u32,
    ) -> Vec<Route> {
        if token_in == token_out {
            return vec![];
        }

        let forward_depth = (max_hops + 1) / 2;
        let backward_depth = max_hops - forward_depth;

        let reached_forward = self.search_forward(token_in, forward_depth);
        let reached_backward = self.search_backward(token_out, backward_depth);

        self.combine_paths(token_in, token_out, &reached_forward, &reached_backward)
    }

    /// DFS from start up to max_depth. Returns map: token -> [(path, pool_indices)].
    fn search_forward(
        &self,
        start: &Token,
        max_depth: u32,
    ) -> HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>> {
        let mut reached: HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>> = HashMap::new();
        let mut path = Vec::with_capacity(max_depth as usize + 1);
        let mut pool_indices = Vec::with_capacity(max_depth as usize);
        let mut visited = HashSet::new();

        self.dfs_forward(
            start,
            max_depth,
            0,
            &mut path,
            &mut pool_indices,
            &mut visited,
            &mut reached,
        );

        reached
    }

    fn dfs_forward(
        &self,
        current: &Token,
        max_depth: u32,
        depth: u32,
        path: &mut Vec<Token>,
        pool_indices: &mut Vec<usize>,
        visited: &mut HashSet<Token>,
        reached: &mut HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>>,
    ) {
        path.push(current.clone());
        visited.insert(current.clone());

        reached
            .entry(current.clone())
            .or_default()
            .push((path.clone(), pool_indices.clone()));

        if depth < max_depth {
            if let Some(edges) = self.graph.get(current) {
                for &(pool_idx, ref next_token) in edges {
                    if !visited.contains(next_token) {
                        pool_indices.push(pool_idx);
                        self.dfs_forward(
                            next_token,
                            max_depth,
                            depth + 1,
                            path,
                            pool_indices,
                            visited,
                            reached,
                        );
                        pool_indices.pop();
                    }
                }
            }
        }

        path.pop();
        visited.remove(current);
    }

    /// DFS from start (token_out) up to max_depth. Returns map: token -> [(path, pool_indices)].
    /// path goes from token_out toward token_in (graph is undirected).
    fn search_backward(
        &self,
        start: &Token,
        max_depth: u32,
    ) -> HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>> {
        let mut reached: HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>> = HashMap::new();
        reached
            .entry(start.clone())
            .or_default()
            .push((vec![start.clone()], vec![]));

        if max_depth == 0 {
            return reached;
        }

        let mut path = Vec::with_capacity(max_depth as usize + 1);
        let mut pool_indices = Vec::with_capacity(max_depth as usize);
        let mut visited = HashSet::new();

        self.dfs_backward(
            start,
            max_depth,
            0,
            &mut path,
            &mut pool_indices,
            &mut visited,
            &mut reached,
        );

        reached
    }

    fn dfs_backward(
        &self,
        current: &Token,
        max_depth: u32,
        depth: u32,
        path: &mut Vec<Token>,
        pool_indices: &mut Vec<usize>,
        visited: &mut HashSet<Token>,
        reached: &mut HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>>,
    ) {
        path.push(current.clone());
        visited.insert(current.clone());

        if depth > 0 {
            reached
                .entry(current.clone())
                .or_default()
                .push((path.clone(), pool_indices.clone()));
        }

        if depth < max_depth {
            if let Some(edges) = self.graph.get(current) {
                for &(pool_idx, ref next_token) in edges {
                    if !visited.contains(next_token) {
                        pool_indices.push(pool_idx);
                        self.dfs_backward(
                            next_token,
                            max_depth,
                            depth + 1,
                            path,
                            pool_indices,
                            visited,
                            reached,
                        );
                        pool_indices.pop();
                    }
                }
            }
        }

        path.pop();
        visited.remove(current);
    }

    fn combine_paths(
        &self,
        token_in: &Token,
        token_out: &Token,
        reached_forward: &HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>>,
        reached_backward: &HashMap<Token, Vec<(Vec<Token>, Vec<usize>)>>,
    ) -> Vec<Route> {
        let mut routes = Vec::new();

        for (meet_token, forward_paths) in reached_forward {
            let backward_paths = match reached_backward.get(meet_token) {
                Some(p) => p,
                None => continue,
            };

            for (path_f, pools_f) in forward_paths {
                for (path_b, pools_b) in backward_paths {
                    if path_f.last() != Some(meet_token) || path_b.last() != Some(meet_token) {
                        continue;
                    }

                    let path_f_set: HashSet<&Token> = path_f.iter().collect();
                    let path_b_excluding: Vec<&Token> = path_b.iter().filter(|t| *t != meet_token).collect();
                    if path_b_excluding.iter().any(|t| path_f_set.contains(t)) {
                        continue;
                    }

                    let path_b_rev: Vec<Token> = path_b.iter().rev().cloned().collect();
                    let mut full_path = path_f.clone();
                    for t in path_b_rev.iter().skip(1) {
                        full_path.push(t.clone());
                    }

                    let mut full_pools: Vec<usize> = pools_f.clone();
                    let mut pools_b_rev: Vec<usize> = pools_b.iter().copied().rev().collect();
                    full_pools.append(&mut pools_b_rev);

                    let pools: Vec<UniswapV2Pair> = full_pools
                        .iter()
                        .map(|&i| self.pools[i].clone())
                        .collect();

                    if let Ok(route) = Route::new(pools, full_path) {
                        if route.path.first() == Some(token_in)
                            && route.path.last() == Some(token_out)
                            && !routes.iter().any(|r: &Route| {
                                r.path == route.path
                                    && r.pools.len() == route.pools.len()
                                    && r.pools
                                        .iter()
                                        .zip(route.pools.iter())
                                        .all(|(a, b)| a.address == b.address)
                            })
                        {
                            routes.push(route);
                        }
                    }
                }
            }
        }

        routes
    }

    fn gas_cost_wei(gas_price_gwei: u64, gas_estimate: u64) -> Option<u128> {
        (gas_price_gwei as u128)
            .checked_mul(GWEI_PER_WEI)
            .and_then(|g| g.checked_mul(gas_estimate as u128))
    }

    /// Compare all routes with detailed breakdown.
    pub fn compare_routes(
        &self,
        token_in: &Token,
        token_out: &Token,
        amount_in: u128,
        gas_price_gwei: u64,
        max_hops: u32,
    ) -> Result<Vec<RouteComparison>, RouteError> {
        let routes = self.find_all_routes(token_in, token_out, max_hops);
        let mut comparisons = Vec::with_capacity(routes.len());

        for route in routes {
            let gross_output = match route.get_output(amount_in) {
                Ok(amt) => amt.raw,
                Err(_) => continue,
            };
            let gas_estimate = route.estimate_gas();
            let gas_cost = match Self::gas_cost_wei(gas_price_gwei, gas_estimate) {
                Some(c) => c,
                None => continue,
            };
            let output_token = route.path.last().cloned().expect("valid route has non-empty path");
            let net_output = if output_token == Token::native_eth() {
                gross_output.saturating_sub(gas_cost)
            } else {
                gross_output
            };

            comparisons.push(RouteComparison {
                route,
                gross_output,
                gas_estimate,
                gas_cost,
                net_output,
            });
        }

        comparisons.sort_by(|a, b| {
            b.net_output
                .cmp(&a.net_output)
                .then_with(|| b.gross_output.cmp(&a.gross_output))
                .then_with(|| a.route.num_hops().cmp(&b.route.num_hops()))
        });

        Ok(comparisons)
    }

    /// Find route that maximizes NET output (after gas). Returns (best_route, net_output).
    pub fn find_best_route(
        &self,
        token_in: &Token,
        token_out: &Token,
        amount_in: u128,
        gas_price_gwei: u64,
        max_hops: u32,
    ) -> Result<Option<(Route, u128)>, RouteError> {
        let comparisons = self.compare_routes(token_in, token_out, amount_in, gas_price_gwei, max_hops)?;
        Ok(comparisons
            .into_iter()
            .next()
            .map(|c| (c.route, c.net_output)))
    }
}

#[derive(Debug, Clone)]
pub struct RouteComparison {
    pub route: Route,
    pub gross_output: u128,
    pub gas_estimate: u64,
    pub gas_cost: u128,
    pub net_output: u128,
}
