#!/usr/bin/env node

// author: takeshix@adversec.com
// modified by: skinner927@gmail.com
(function() {
  'use strict';

  const HOST = 'http://localhost:8081/';

  const Zombie = require('zombie');
  const fs = require('fs');
  const chalk = require('chalk');

  Zombie.silent = true;

  let bot = new Zombie();

  var enableLogging = true;
  function log(){
    if(enableLogging){
      console.log.apply(this, arguments);
    }
  }
  

  // Hookup our listeners
  bot.on('error', function(error){
    console.error(chalk.red('ERROR:'), error);
  });

  bot.on('alert', function(message){
    log(chalk.bgMagenta('ALERT -- ALERT -- ALERT'));
    log(chalk.magenta(message));
  });

  bot.on('submit', function(){
    log(chalk.yellow('Submitting Form'));
  });

  bot.on('redirect', function(request){
    if(request.url.indexOf(HOST) === 0){
      return;
    }
    log(chalk.bgBlue('Redirect'));
    log(request);
  });

  bot.on('link', function(url){
    log(chalk.bgBlue('Link'));
    log(url);
  });


  // Get all files from the comments directory
  fs.readdirSync('./comments')
    // Pick out just unique user names
    .reduce(function(users, filename, i, files) {

      if(filename[0] !== '.'){
        let user = filename.split('-')[0];

        users[user] = true;
      }

      return files.length - 1 === i ? Object.keys(users) : users;
    }, {})
    // Loop over each user and visit their page
    .forEach(function(user) {
      console.log(chalk.green.bold('================================='));
      console.log(chalk.green.bold('Visiting: ' + user));

      bot.setCookie({
        name: 'botid',
        value: 'mag1c_c00k1e007',
        domain: 'localhost'
      });
      bot.setCookie({
        name: 'name',
        value: user,
        domain: 'localhost'
      });

      //bot.debug();
      enableLogging = true;
      bot.visit(HOST, function() {
        // Don't log anything after we post because it'll probably be the exact same stuff
        enableLogging = false;
        bot.fill("username", "admin").fill("comment", "hilarious!").pressButton("Post it!", function() {})
      });
    });

})();
