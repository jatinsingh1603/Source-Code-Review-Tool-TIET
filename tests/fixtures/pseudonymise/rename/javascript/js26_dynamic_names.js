const settings = { festivalBonusRate: 5 };

function readBonus() {
  return settings["festivalBonusRate"];
}

function readOther(config) {
  return config["loyaltyPointsTotal"];
}
