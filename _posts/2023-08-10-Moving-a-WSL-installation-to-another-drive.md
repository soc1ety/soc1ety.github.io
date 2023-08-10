---
title: Moving a WSL installation to another drive
categories: [WINDOWS]
tags: [windows, wsl, tutorial]
---


# Moving a WSL installation to another drive

[![image.png](https://i.postimg.cc/wTCyp7s5/image.png)](https://postimg.cc/ppBXQVCy)


---  
# Preface 

It's been a while since I hadn't written something so I guess it's time to come up with some boring stuff to celebrate isn't it ?  
This blogpost will be very short but I found it pretty interesting because it's about something I just did for my use case and now I know it will be somewhere if I ever need to do it again.  

So if just like me you like reinstalling your system pretty often and you can't be arsed to make backups, I think it might be useful since it takes at most five minutes to be done (or you can do it in a second by :q! this blogpost).  

Now let's get to the very important stuff, enjoy !  

--- 
# Disclaimer 

The following procedure is system **destructive**, meaning that it will still remove all files in your virtual system, but your core system will remain the same.  
Please do backups (forget what I've said above) and proceed to the next step if you're good with it.

As stated before I already did it but for the sake of comprehension I will still provide screenshots and everything needed, let's get to it.

Credits to <a href="https://superuser.com/questions/1701175/installing-ubuntu-on-mnt-d-with-wsl">this</a> post I used to make this blog post, it's the exact same procedure but I'll do my best to make it easier with the aforementioned screenshots.  

--- 
# Quick overview of what we're about to do  

If you still didn't catch what we are going to do, here is a tl;dr made up of three main steps : 

- We will make a backup of the current installation (in my case Ubuntu but it will work for any distribution installed)
- We will restore it to whatever drive you want, here I will use my SSD denoted by the `D:` letter.
- Once everything is successful, we will remove the initial installation to free up space (phew) and be done with this tutorial.  

As stated above, I am using Ubuntu 22.04 LTS (at the time of the post's release) but it will work with Debian, Arch Linux, OpenSUSE or any other obscure distribution as long as you run it through WSL2.  

--- 

# Beginning of the tutorial  

## Creating the base structure on the other disk

First we are going to create two directories under the targeted disk, here I will use `D:` but replace it with the letter assigned to yours. 

Open a powershell terminal and enter the following three commands : 

[![2.png](https://i.postimg.cc/cLZrkP30/2.png)](https://postimg.cc/1fCmfCMj)  

Once you've created those two directories, your current structure should be as follow :  

[![3.png](https://i.postimg.cc/B63YjSLR/3.png)](https://postimg.cc/zLdSM1kk)


## Exporting and importing your installation to the new location

Once done with the directories creation, you should still be in the `/images` directory, stay inside and get to the next step.  

We're already 80% done (I told you it wouldn't take ages) ! Now we're about to export your current installation (that is still on your `C:` drive) to a new one located on your second disk. 

Still on the same powershell session (or a new one if you've been impatient) do the following :  

[![4.png](https://i.postimg.cc/4NnG5gwr/4.png)](https://postimg.cc/ZCkXbXGc)

The first line creates the backup (`ubuntu.tar`) from your existing installation , while the second creates a new WSL instance named Ubuntu2204 (instead of the default Ubuntu) on your newly selected drive (still `D:` in my case). 


## Starting the new instance and deleting the old one

If you've done everything correctly until here you should have only saw the splendid word `successful` appearing on your screen, if not, please double check the previous commands + that you used the same name everywhere.  
If it still doesn't work, I will not pay attention to any death threat and assume that I'm not dumb at explaining things... I hope...  

So, once you exported & imported your new installation successfully, let's actually run it and make a couple of changes so it will be able to detect the user you created during the first initial setup. 

Still in a powershell session (I promise we're almost done), do `wsl ~ -d <your_distribution_name> (Ubuntu2204 for me)`

You should now be logged in as root since WSL2 doesn't "remember" the user you used at the very start : 

[![5.png](https://i.postimg.cc/kGTbdmt0/5.png)](https://postimg.cc/vx6BWChh)

Now, edit the WSL configuration file located at `/etc/wsl.conf` by doing : `sudo -e /etc/wsl.conf` 

By default you should only have the `[boot]` entry so you will have to add the `[user]` as shown below, by adding the name of your current user accordingly.

[![6.png](https://i.postimg.cc/wTdq9PkP/6.png)](https://postimg.cc/kDf3cTzF)

Once that is done, save and exit nano by doing `Ctrl+O`, Enter then `Ctrl+X`.  

Now, save and exit Ubuntu and do `wsl --terminate <your_distribution_name>` then `wsl ~ -d your_distribution_name` in your powershell session.  

Now, when you type wsl ~ you will start in that instance, you can confirm by running `wsl --list`. 

Once you have **confirmed** that everything is working as it should and you're sure you didn't miss anything (in that case you're free to start over again,), you can remove the original by doing `wsl --unregister <your_previous_distribution_name>`.  

Please remember that everything will be gone for good and you won't be able to recover it, so if you got any doubt take another 30 minutes to do it again so you're sure everything will be done correctly. 

You should now be running your WSL instance from your new installation in your second drive ! You can now rinse and repeat the process if you want to try some other distributions and whatnot.  

--- 
# Some more useless words 

To conclude, I hope that this new blog post coming from nowhere has provided you with valuable information. I hope that you enjoyed reading it and (I'm asking too much I think) also gained a clear understanding of what I tried my best to explain.

Thank you for joining me on this short journey with Windows stuff ! More is to come on various subjects and I will do my best to be more consistent with this blog.  
Until then, happy reading and see you soon !  

--- 

# References 

- https://superuser.com/questions/1701175/installing-ubuntu-on-mnt-d-with-wsl
- https://learn.microsoft.com/en-us/windows/wsl/
