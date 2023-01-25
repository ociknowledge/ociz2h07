/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
   DESCRIPTION
    This class will is a wrapper for bunyan logger module

   MODIFIED    (MM/DD/YY)
    xinnwang    12/06/16 - Refacotoring
    junyhe      11/22/16 - Creation
 */
'use strict';

// third party logger module
const buyanLogger = require('bunyan');
var level = 'error';
class Logger {
  /**
   * Get logger instance for specified name
   */
  static getLogger(name) {
      if(!this.logger){
          name = 'passport-idcs';
          this.logger = buyanLogger.createLogger({
              name,
              streams: [{
                  level: 'error',
                  name: 'error',
                  path: 'error.log'
              }, {
                  stream: process.stdout,
                  level: 'warn',
                  name: 'console',
              }]
          });

      }
      this.logger.level(level);
      return this.logger;
  }

  static setLevel(vLevel) {
    level = vLevel;
  }
}

module.exports = Logger;
