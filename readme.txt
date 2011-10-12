=== ShieldPass two-factor authentication ===
Contributors: shieldpass
Tags: authentication, security, login
Requires at least: 2.0.2
Tested up to: 3.2.1
Stable tag: 3.2.1

This plugin adds shieldpass two-factor authentication using access cards for different WordPress admin access users into the Wordpress login page.

== Description ==

ShieldPass is a highly secure two factor authentication system based on the http://www.passwindow.com authentication method. Users buy a low cost ShieldPass access card from https://www.shieldpass.com with a secret unique visual key. 
Once the plugin is configured and after the username and password is enter the user will be prompted to enter a dynamically changing one time password after superimposing their access card on the screen of their computer or mobile device.

The same shieldpass access card can be configured by the user to work in multiple online access points such as other blogs or websites including joining the growing ShieldPass secured client networks.

The ShieldPass transaction authenticated challenges are constructed in such a way so as to reduce the information loss from each challenge so that even a long term hacker analysis of the challenges and responses will fail to give an attacker enough information to determine the secret key pattern, leaving a hacker with no online attacks against the method commonly utilized against other authentication systems such as the infamous man-in-the-middle attack.

The simplicity of the method eliminates hi-tech hacking methods which bypass software authentication and electronic hardware authentication such as mobile based two factor authentication.

ShieldPass has the convenience of always being able to work even when travelling, out of mobile range or in a different country where the user does not have their mobile network. It also works equally well on any device with a normal display using an ordinary browser which can display the challenge image. Plus they fit securely in an ordinary wallet or purse with your normal id cards. 

The access cards contain no electronics or limited lifespan and can be relied upon in the most rugged conditions where normal electronics will fail.

Card costs and subscription are less than $10 and postage anywhere in the world is included in the price.

`[youtube http://www.youtube.com/watch?v=ZrRMHG-jZ-8]`


== Installation ==

1. Create an account at https://www.shieldpass.com and buy your ShieldPass access cards.

1. After signing up and activating your account, download the ShieldPass WordPress plugin zip file.

1. Install and activate the ShieldPass WordPress plugin.

1. In the users setting, select ShieldPass Configuration and fill in the "Public Key" and "Secret Key" generated in your ShieldPass administrative panel. Also, enter the WordPress user and corresponding ShieldPass user ID card value that you'd like to require ShieldPass login.

1. Log out of your WordPress. Upon logging back in, you'll be prompted to superimpose your access card using ShieldPass's two-factor authentication service.



== Frequently Asked Questions ==

= Where do I configure the shieldpass plugin? =

The ShieldPass configuration panel is found under "Users" on the left hand side of the admin panel. 


== Screenshots ==

1. The ShieldPass configuration panel includes public / secret key entry as well as multiple user configuration.

== Changelog ==

= 2.1 =
* Nonces used in forms.

== Upgrade Notice ==

= 2.1 =
Secure nonces added to admin configuration form.



