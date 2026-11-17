# StandardVault

TRON 主金库合约。一份合约管一个资金池，不能升级。

钱只能打到白名单、利润地址或避险地址。改白名单、改每天上限、换出款钥匙、换管理地址，要两个管理地址分别签名。

编译器：solc 0.8.26。优化打开，runs 200，viaIR，EVM 版本 istanbul。

主网合约：`TGk6UxkHpNL7s5mGcs8HAuLPdZiFpxQhJ1`

许可证：MIT
