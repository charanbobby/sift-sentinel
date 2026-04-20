Simulated network intrusion as part of research to develop artificial intelligence / machine learning for post-breach triage.

All information contained within the image (including but not limited to usernames and IP addresses) is synthetic.

Simulated UK-based small office network running from Sept 2023 to Feb 2024. The administrator opened RDP to facilitate working from home.  As part of the scenario, on 12th Feb 2024 discovered the server was no longer responding with 'Red Petya' ransomware displayed on the screen.  Forensic experts were engaged, the disk decrypted and a forensic image taken in EnCase E01 format (also known as Expert Witness Format) 


Image may be viewed using most forensic tools:

	Forensic ToolKit (Commercial)
	EnCase (Commercial)
	FTK Imager (Free - simple disk view)
	Autopsy (Open source)
	libewf (Available as part of most Linux distributions)
	plaso (aka log2timeline)



It is anticipated that this collection may be used for teaching so analysis of the image is left as an exercise for the reader.  As with every incident response exercise, care should be taken to protect your systems from potential malware.

Many thanks to my PhD supervisors, Prof Adrian Hopgood, Dr Patrick Wong and Dr Ian Kennedy.  Thanks also to CMU Ghosts, VirtualBox, generatedata.com, Kali Linux, GreyNoise.io and many more.

md5sums:

6f912bbaa1500f4556bd6b4fa8466f02  20240212-decrypted-Windows_Server_2022.E01
ef559f911cfb1ff5c32bb2fc67f324cb  20240212-decrypted-Windows_Server_2022.E02
41f89be64b3ef383a92098e19afba7a0  20240212-decrypted-Windows_Server_2022.E03
092c9ab696deb156513147bfa562c773  20240212-decrypted-Windows_Server_2022.E04
57fdb6ac59c612087e3ee92e609b9aab  20240212-decrypted-Windows_Server_2022.E05
3d9d67cfa7408756aef3c7d2f4944267  20240212-decrypted-Windows_Server_2022.E06
ef079d9e318d8c25fb3de10674e13e79  20240212-decrypted-Windows_Server_2022.E07


Released without warranty under CC-BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike).  This license lets others remix, tweak, and build upon this work non-commercially, as long as they credit me and license their new creations under the identical terms.


For further information, including ground truth for research purposes, please contact Benjamin Donnachie using benjamin.donnachie@open.ac.uk