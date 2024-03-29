#!/usr/bin/env node
"use strict";

const chalk = require( "chalk" );
const dotenv = require( "dotenv" );
const authClient = require( "../src/authClient" );

// read in settings
dotenv.config();

const config = {
 authUrl: process.env.AUTHORIZE_URL,
 tokenUrl: process.env.TOKEN_URL,
 clientId: process.env.CLIENT_ID,
 scopes: process.env.SCOPES,
 redirectUrl: process.env.REDIRECT_URL
};

const main = async () => {
 try {
   const auth = authClient( config );
   const { token, userInfo } = await auth.executeAuthFlow();
   console.log( token, userInfo );
   console.log( chalk.bold( "You have successfully authenticated your CLI application!" ) );
 } catch ( err ) {
   console.log( chalk.red( err ) );
 }
};

main();
