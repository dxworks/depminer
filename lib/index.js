const {depminer} = require("./lib");
const {Command} = require("commander");

exports.depminerCommand = new Command()
  .name('depminer')
  .description('Run the Depminer tool')
  .allowUnknownOption()
  .action(depminer)
