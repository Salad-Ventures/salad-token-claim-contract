import { ethers } from "hardhat";

async function main() {
  let admin = "0x3C971ccf2F799EBa65EA25E7461D7Ad438c811aD";
  
  const generalLimitGroup = [400,400,500,400,400];

  const genesisLimitGroup = [800,800,1000,800,800];

  const listGroup = [1,2,3,4,5];
  const feeSeller = (10 * 10**18).toString();

  const listGeneralGroup = [
    [100,100,100,100],
    [100,100,100,100],
    [100,100,100,100,100],
    [100,100,100,100],
    [100,100,100,100]
  ];

  const listGenesisGroup = 
  [
    [200,200,200,200],
    [200,200,200,200],
    [200,200,200,200,200],
    [200,200,200,200],
    [200,200,200,200]
  ];

  const generalPrice = (10**18).toString();
  const genesisPrice = (10**18).toString();
  const farmPrice = (10**18).toString();
  const bitPrice = (10**18).toString();

  // Deploy contract token (OAS) 
  const Accessories = await ethers.getContractFactory("Accessories");
  const accessories = await Accessories.deploy();
  accessories.deployed();

  const Coach = await ethers.getContractFactory("Coach");
  const coach = await Coach.deploy();
  coach.deployed();

  const General = await ethers.getContractFactory("GeneralHash");
  const general = await General.deploy();
  general.deployed();

  const Genesis= await ethers.getContractFactory("GenesisHash");
  const genesis = await Genesis.deploy();
  general.deployed();

  const HashChipNFT= await ethers.getContractFactory("HashChipNFT");
  const hashChipNFT = await HashChipNFT.deploy();
  hashChipNFT.deployed();

  const MonsterCrystal= await ethers.getContractFactory("MonsterCrystal");
  const monsterCrystal = await MonsterCrystal.deploy();
  monsterCrystal.deployed();
  
  const MonsterMemory= await ethers.getContractFactory("MonsterMemory");
  const monsterMemory = await MonsterMemory.deploy();
  monsterMemory.deployed();

  const Skin= await ethers.getContractFactory("Skin");
  const skin = await Skin.deploy();
  skin.deployed();

  const Monster= await ethers.getContractFactory("Monster");
  const monster = await Monster.deploy();
  monster.deployed();

  const TrainingItem= await ethers.getContractFactory("TrainingItem");
  const trainingItem = await TrainingItem.deploy("baseURL");
  trainingItem.deployed();
  
  const RegenerationItem= await ethers.getContractFactory("RegenerationItem");
  const regenerationItem = await RegenerationItem.deploy("baseURL");
  regenerationItem.deployed();
  
  const FusionItem= await ethers.getContractFactory("FusionItem");
  const fusionItem = await FusionItem.deploy("baseURL");
  fusionItem.deployed();

  const EhanceItem= await ethers.getContractFactory("EhanceItem");
  const ehanceItem = await EhanceItem.deploy("baseURL");
  ehanceItem.deployed();

  const Shop= await ethers.getContractFactory("ReMonsterShop");
  const shop = await Shop.deploy(admin,generalPrice,genesisPrice,farmPrice,bitPrice);
  shop.deployed();

  const ReMonsterMarketplace= await ethers.getContractFactory("ReMonsterMarketplace");
  const reMonsterMarketplace = await ReMonsterMarketplace.deploy(feeSeller, admin);
  reMonsterMarketplace.deployed();

  const ReMonsterFarm= await ethers.getContractFactory("ReMonsterFarm");
  const reMonsterFarm = await ReMonsterFarm.deploy("Farm", "FARM", 5000);
  reMonsterFarm.deployed();

  const TokenXXX= await ethers.getContractFactory("TokenXXX");
  const tokenXXX = await TokenXXX.deploy("xxx", "xxx");
  tokenXXX.deployed();

  // Log results
  console.log(`ADDRESS_CONTRACT_ACCESSORIES: ${accessories.address}`);
  console.log(`ADDRESS_CONTRACT_COACH: ${coach.address}`);
  console.log(`ADDRESS_CONTRACT_GENERAL: ${general.address}`);
  console.log(`ADDRESS_CONTRACT_GENESIS: ${genesis.address}`)
  console.log(`ADDRESS_CONTRACT_HASHCHIP: ${hashChipNFT.address}`)
  console.log(`ADDRESS_CONTRACT_CRYSTAL: ${monsterCrystal.address}`)
  console.log(`ADDRESS_CONTRACT_MEMORY: ${monsterMemory.address}`)
  console.log(`ADDRESS_CONTRACT_SKIN: ${skin.address}`)
  console.log(`ADDRESS_CONTRACT_MONSTER: ${monster.address}`)
  console.log(`ADDRESS_CONTRACT_TRAINING_ITEM: ${trainingItem.address}`)
  console.log(`ADDRESS_CONTRACT_REGENERATION_ITEM: ${regenerationItem.address}`)
  console.log(`ADDRESS_CONTRACT_FUSION_ITEM: ${fusionItem.address}`)
  console.log(`ADDRESS_CONTRACT_ENHANCE_ITEM: ${ehanceItem.address}`)
  console.log(`ADDRESS_CONTRACT_SHOP: ${shop.address}`)
  console.log(`ADDRESS_CONTRACT_MARKET: ${reMonsterMarketplace.address}`)
  console.log(`ADDRESS_CONTRACT_FARM: ${reMonsterFarm.address}`)
  console.log(`ADDRESS_CONTRACT_TOKEN_XXX: ${tokenXXX.address}`)

  // Set init contract Accessories
  await accessories.setMonsterItem(ehanceItem.address);
  // Set init contract Coach
  await coach.setMonsterContract(monster.address);
  await coach.setMonsterMemory(monsterMemory.address);

  /* Set init contract Genesis Hash*/
  // Set detail limit group
  for(let i=0; i< genesisLimitGroup.length; i++){
    await genesis.initSetDetailGroup(i+1, genesisLimitGroup[i]);
  }
  // Set detail specie group A
  for(let i=0; i< genesisLimitGroup.length; i++){
    let arr = listGenesisGroup[i];
    for(let j=0;j < arr.length; j++) {
      await genesis.initSetSpecieDetail(i+1,j+1, arr[j]);
    }
  }
  // for(let i =0; i < listGroup.length; i++ ){
  //   await genesis.createMarketingBoxWithType(admin, listGroup[i]);
  // }
  // for(let i =0; i< listGroup.length; i++) {
  //   await genesis.createMarketingBox(admin, listGroup[i]);
  // }

  /* Set init contract General Hash*/
  // Set detail limit group
  for(let i=0; i< generalLimitGroup.length; i++){
    await general.initSetDetailGroup(i+1, generalLimitGroup[i]);
  }
  // Set detail specie group A
  for(let i=0; i< generalLimitGroup.length; i++){
    let arr = listGeneralGroup[i];
    for(let j=0;j < arr.length; j++) {
      await general.initSetSpecieDetail(i+1,j+1, arr[j]);
    }
  }  
  // for(let i =0; i< listGroup.length; i++) {
  //   await general.createMarketingBox(admin, listGroup[i]);
  // }

  /* Set init contract Monster crystal*/
  await monsterCrystal.initSetMonsterContract(monster.address);
  await monsterCrystal.initSetMonsterMemory(monsterMemory.address);
  await monster.grantRole(monster.MANAGEMENT_ROLE(), monsterCrystal.address);
  await monsterMemory.grantRole(monsterMemory.MANAGEMENT_ROLE(), monsterCrystal.address);

  // Set init contract Memory
  await monsterMemory.grantRole(monsterMemory.MANAGEMENT_ROLE(), coach.address);
  await monsterMemory.grantRole(monsterMemory.MANAGEMENT_ROLE(), monster.address);
  await monsterMemory.grantRole(monsterMemory.MANAGEMENT_ROLE(), monsterCrystal.address);

  // Set init contract Monster
  await monster.grantRole(monster.MANAGEMENT_ROLE(), coach.address);
  await monster.grantRole(monster.MANAGEMENT_ROLE(), monsterCrystal.address);
  await monster.initSetTokenBaseContract(monsterCrystal.address);
  await monster.initSetExternalContract(monsterCrystal.address);
  await monster.initSetGeneralHashContract(general.address);
  await monster.initSetGenesisHashContract(genesis.address);
  await monster.initSetHashChipContract(hashChipNFT.address);
  await monster.initSetMonsterMemoryContract(monsterMemory.address);
  await monster.initSetMonsterItemContract(regenerationItem.address);
  await monster.initSetTreasuryAdress(admin);
  // Set init contract General
  await general.grantRole(general.MANAGEMENT_ROLE(), monster.address);
  // Set init contract Genesis
  await genesis.grantRole(genesis.MANAGEMENT_ROLE(), monster.address);
  // Set init contract Item
  await regenerationItem.grantRole(regenerationItem.MANAGEMENT_ROLE(), monster.address);
  await ehanceItem.grantRole(ehanceItem.MANAGEMENT_ROLE(), accessories.address);
  // Set init contract HashChip
  await hashChipNFT.grantRole(hashChipNFT.MANAGEMENT_ROLE(), monster.address);
  // shop
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});