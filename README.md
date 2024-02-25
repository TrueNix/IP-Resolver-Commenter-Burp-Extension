## IP Resolver Commenter for Burp Suite

**Empower your Burp Suite Intruder analysis with resolved IP addresses!**

This Python-powered Burp Suite extension automatically injects resolved IP addresses into the comments field of each Intruder request. Ditch the tab-hopping and enjoy a streamlined, informed analysis experience directly within the Intruder interface.

### Features that rock your world:

* **⚡️ Dynamic IP Resolution:** Effortlessly resolves IP addresses for every hostname encountered in your Intruder payload.
* **✨ Seamless Comment Integration:** Appends the resolved IP address to the comment field of each request, making it instantly visible in the Intruder results table.
* **🪄 Frictionless Usage:** Integrates flawlessly into your Intruder workflow, requiring no additional steps to view IP addresses.

### ⚙️ Requirements:

* Burp Suite (Community or Professional)
* Jython configured within Burp Suite to run Python scripts

### ⬇️ Installation Steps:

1. **Verify Jython:** Ensure Jython is properly installed and configured within your Burp Suite environment.
2. **Grab the Script:** Download the IP Resolver Commenter script from the GitHub repository link here!: [https://github.com/TrueNix/IP-Resolver-Commenter-Burp-Extension]
3. **Navigate to Extensions:** In Burp Suite, head to the **Extender** tab > **Extensions** sub-tab.
4. **Add the Extension:** Click **Add**, select **Python** as the extension type, and choose the downloaded script.

### 🪄 Usage is Magic:

Once installed, the extension becomes your silent partner, automatically processing all HTTP requests generated by the Intruder. It resolves the IP address for each request's hostname and whispers this information into the comment field. These comments then appear in the Intruder's results table, granting you instant access to IP addresses without any extra effort.

###  Contributions Welcome!

Feel free to join the community and contribute to the IP Resolver Commenter's evolution! Whether you're a bug-squashing hero, a functionality-enhancing mastermind, or a feature-suggesting visionary, your input is invaluable. Fork the repository on GitHub, make your changes, and submit a pull request to share your brilliance.

### ⚖️ License:

This project is licensed under the MIT License. See the `LICENSE.md` file for details.

