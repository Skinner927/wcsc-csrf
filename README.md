xss-board
=========

This is an example of a simple XSS challenge using Zombie.js (http://zombie.labnotes.org/). 
The bot will visit the website every three minutes and executes all the Javascript code it finds.

Frequency can be changed by editing the `.sh` or `.bat` file and modifying the `sleep` value.

The website is a simple comment board. Everyone that visits for the first time 
will get their own unique page so you can have multiple people using this site 
and their comments will not overlap. You can also use an easy to remember name 
by changing the `name` param in the URL. 

The bot will visit each segmented page starting once a comment has been made.

XSS works in Chrome as of March/19/2016 with XSS protection turned off via PHP 
headers.

### Configure It

Open `index.php`, at the top of the file you can edit `WINNINGFLAG` which is a 
string that is displayed only on the bot's page inside a span with `id='flag'`.

You can also adjust the bot's cookie with `BOTCOOKIE`. Dont forget to update 
this value in `bot.js` as well.

The comments directory needs to be writable for the www user.

### Run It

When you first clone the repo, install node deps with `npm install`

Run `run.sh` or `run.bat` depending on your OS. 


### Requirements

PHP 5
Node

