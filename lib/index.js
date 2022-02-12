const {depminer} = require("./lib");
const {Command} = require("commander");

exports.depminerCommand = new Command()
  .name('depminer')
  .description('Run the Depminer tool')
  .option('-wd --working-directory', 'Selects the directory where Depminer will store the results folder.' +
    ` Defaults to the location where Depminer is installed: ${__dirname}. If set to true it will use the current working directory process.cwd()`,
    false)
  .allowUnknownOption()
  .action(depminer)
