import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

const func: DeployFunction = async (hre: HardhatRuntimeEnvironment) => {
  const { deployments, getNamedAccounts } = hre as any;
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  const INSTITUTION_NAME = process.env.INSTITUTION_NAME     || "Đại học ABC";
  // Ví nhà trường: toàn quyền — cấp bằng, thu hồi, pause
  const SCHOOL_ADMIN     = process.env.SCHOOL_ADMIN_ADDRESS || deployer;

  const result = await deploy("DiplomaRegistry", {
    from: deployer,
    args: [INSTITUTION_NAME, SCHOOL_ADMIN],
    log: true,
  });

  console.log(`DiplomaRegistry deployed : ${result.address}`);
  console.log(`School admin             : ${SCHOOL_ADMIN}`);
};

export default func;
func.tags = ["DiplomaRegistry"];