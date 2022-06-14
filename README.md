# REdiREKT
Code-base to go with academic paper "REdiREKT: Extracting Malicious Redirections from Exploit Kit Traffic" available @ https://pure.qub.ac.uk/en/publications/redirekt-extracting-malicious-redirections-from-exploit-kit-traff and short video presentation and tool demo here: https://www.youtube.com/watch?v=DIXRouNfq6E

REdiREKT uses Zeek to process PCAPs and maps HTTP redirections (header and content-based). A combination of HTTP, redirect content-based features are extracted from each domain within a redirect chain and stored (SQLite/JSON/CSV) for future ML-based malware detection research.

PCAPs HAVE NOT BEEN INCLUDED DUE TO SIZE: malicious PCAPs were sourced from malware-traffic-analysis.com and broad-analysis.com, each of which were manually analysed and test cases created. Benign PCAPs were generated with custom Windows 10 honeypot (some code for this is also in repo).

I don't currently don't have much time to document the repo but the code should be fairly well commented :) Any major issues/questions then I'll do my best to help if time permits.

UPDATE: Added ML-Training folder with IPython Notebooks and features for LSTM RNN training. They are a bit of a mess as I often didn't clean up previous cells and lost track.