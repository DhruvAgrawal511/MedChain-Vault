async function main() {
  const BlockVault = await ethers.getContractFactory("BlockVault");
  const contract = await BlockVault.deploy();
  await contract.waitForDeployment();
  console.log("BlockVault deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
