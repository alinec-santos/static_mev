// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VulnerableSwapper {
    IUniswapV2Router02 public uniswapRouter;
    address public tokenIn;
    address public tokenOut;

    constructor(address _router, address _tokenIn, address _tokenOut) {
        uniswapRouter = IUniswapV2Router02(_router);
        tokenIn = _tokenIn;
        tokenOut = _tokenOut;
    }

    // VULNERABILIDADE AQUI
    // A função aceita apenas a quantidade de entrada.
    // O usuário não tem controle sobre o mínimo que vai receber.
    function badSwap(uint256 amountIn) external {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(address(uniswapRouter), amountIn);

        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        // CRÍTICO: O segundo argumento (amountOutMin) é 0.
        // Isso diz ao Uniswap: "Me dê qualquer quantidade, mesmo que seja 0.000001"
        // Um bot de MEV vai explorar isso instantaneamente.
        uniswapRouter.swapExactTokensForTokens(
            amountIn,
            0, // <--- DETECTOR DEVE APITAR AQUI
            path,
            msg.sender,
            block.timestamp
        );
    }
}