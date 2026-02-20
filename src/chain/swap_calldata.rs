//! Uniswap V2 router swap calldata builder for DEX execution.
//! Produces (calldata, value) for swapExactTokensForTokens or swapExactETHForTokens.

use crate::core::base_types::Address;
use alloy::primitives::{Address as AlloyAddress, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

sol!(
    #[allow(missing_docs)]
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
);

sol!(
    #[allow(missing_docs)]
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);
);

sol!(
    #[allow(missing_docs)]
    function getAmountsOut(
        uint256 amountIn,
        address[] calldata path
    ) external view returns (uint256[] memory amounts);
);

/// Build Uniswap V2 router swap calldata and msg.value.
///
/// - If path[0] == weth: uses swapExactETHForTokens, value = amount_in.
/// - Else: uses swapExactTokensForTokens, value = 0.
pub fn build_swap_calldata(
    path: &[Address],
    amount_in: u128,
    amount_out_min: u128,
    to: &Address,
    deadline: u64,
    weth: &Address,
) -> (Vec<u8>, u128) {
    let path_alloy: Vec<AlloyAddress> = path.iter().map(|a| a.alloy_address()).collect();
    let to_alloy = to.alloy_address();
    let weth_alloy = weth.alloy_address();
    let is_eth_in = path.first().map(|a| a.alloy_address() == weth_alloy).unwrap_or(false);

    if is_eth_in {
        let call = swapExactETHForTokensCall::new((
            U256::from(amount_out_min),
            path_alloy,
            to_alloy,
            U256::from(deadline),
        ));
        (swapExactETHForTokensCall::abi_encode(&call), amount_in)
    } else {
        let call = swapExactTokensForTokensCall::new((
            U256::from(amount_in),
            U256::from(amount_out_min),
            path_alloy,
            to_alloy,
            U256::from(deadline),
        ));
        (swapExactTokensForTokensCall::abi_encode(&call), 0)
    }
}

/// Build calldata for router.getAmountsOut(amount_in, path).
pub fn build_get_amounts_out_calldata(path: &[Address], amount_in: u128) -> Vec<u8> {
    let path_alloy: Vec<AlloyAddress> = path.iter().map(|a| a.alloy_address()).collect();
    let call = getAmountsOutCall::new((U256::from(amount_in), path_alloy));
    getAmountsOutCall::abi_encode(&call)
}

/// Decode getAmountsOut return data to get the last amount (amount out).
pub fn decode_get_amounts_out_return(data: &[u8]) -> Option<u128> {
    let amounts: Vec<U256> = getAmountsOutCall::abi_decode_returns(data).ok()?;
    amounts.last().map(|u| u.to::<u128>())
}
