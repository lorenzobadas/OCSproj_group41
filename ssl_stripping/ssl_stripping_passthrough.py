# This is the version of the code where we don't simply immitate the website



######### Initial setup before entering any credentials or anything, just calling the website ########

# Step 1: Intercept packet from victim

victim_IP = ""
target_server_IP = ""
target_URL = ""

# Extract information from the intercepted packet, so credentials

# Step 2: Initiate a connection with the target HTTPS server

# Receive the answer from the server and remove the "s" from "https"
# Bartek said there are also other steps to do, this is not everything

# Maybe change the IP of the packet to ours? Probably not necessary

# Step 3: Send the packet back to the victim (HTTP) so they can render the website


######### Process the incoming packets from the victim after the initial connection ########
# This is a continious process, so it runs in the background

# Extract the credentials from the received packets

# Print the packets in the console

# Log the credentials into a file