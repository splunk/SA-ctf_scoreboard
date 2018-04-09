# SA-ctf_scoreboard
A capture the flag scoreboard app for Splunk.

This app, along with its companion [admin app](https://github.com/splunk/SA-ctf_scoreboard_admin), allows anyone to run their own jeopardy-style capture the flag (CTF) events. These are the same apps that we at splunk use to run our popular [Spunk Boss of the SOC (BOTS)](https://www.splunk.com/blog/2017/09/06/what-you-need-to-know-about-boss-of-the-soc.html) and Boss of the NOC (BOTN) competitions. The apps include the following features:
  * User/team management
  * Scoring management
  * Comprehensive scoring analytics
  * Fully customizable question/answer sets
  * Hint management
 
The scoring apps run on Splunk Enterprise. If you do not have a Splunk license, these apps can run with full functionality on the Enterprise Trial version of Splunk available at [www.splunk.com](https://www.splunk.com/)

## Installation
1.	Install Splunk Enterprise 
    * Set a strong admin password
    * Set the splunk timezone for the admin user
    * Enable TLS on SplunkWeb
    * Note: Tested with Splunk Enterprise version 7.0.x
