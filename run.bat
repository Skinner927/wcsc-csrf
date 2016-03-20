start "PHP XSS Server" php -S 0.0.0.0:8081

:loop

echo "Running bot"
node bot.js
echo "waiting 1 minute"
sleep 60

goto loop
