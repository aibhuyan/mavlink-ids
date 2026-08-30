# Running the Lab: ArduPilot SITL on WSL2

This guide starts a **simulated drone** and points its MAVLink traffic at our
detector. Nothing here transmits over radio or touches real hardware — it is all
software on localhost.

- **Autopilot:** ArduPilot SITL (software-in-the-loop) — a real ArduPilot flight
  controller compiled to run as a program instead of on a physical board.
- **Runs in:** WSL2 Ubuntu (SITL is Linux-first).
- **Detector runs in:** Windows (our `uv` project), by replaying a captured file.

---

## The network picture

`sim_vehicle.py` launches the simulated drone **and** a MAVProxy ground station.
MAVProxy is our *legitimate operator* — it generates the benign traffic — and it
automatically records the whole session to a `mav.tlog` file.

WSL2 uses **NAT networking** by default: the Linux side has its own private
network, separate from Windows. That isolation is what lets SITL bind its ports
cleanly — but it also means a UDP stream SITL sends to `127.0.0.1` stays *inside*
WSL and never reaches a detector running on Windows.

So instead of a live cross-boundary link, we **capture to a file and analyse it
on Windows**. This is reproducible, needs zero networking config, and is exactly
what the evaluation phase wants:

```
   WSL2 (Ubuntu)                                Windows
   ┌────────────────────────────┐             ┌──────────────────────────┐
   │ SITL drone ── MAVProxy GCS  │             │ mavlink-ids detector     │
   │        (benign traffic)     │  copy file  │ (uv run ...)             │
   │            └─► mav.tlog ────┼── /mnt/c ──►│ data/benign/*.tlog       │
   │                             │             │      │ replay             │
   │                             │             │      ▼ Events → detection │
   └────────────────────────────┘             └──────────────────────────┘
```

> **Do NOT enable WSL2 "mirrored networking".** It shares Windows' reserved port
> ranges with WSL, which makes SITL fail to bind TCP port 5760 ("Address already
> in use") even when nothing is using it. Keep the default NAT networking. If you
> created `C:\Users\<you>\.wslconfig` for mirrored mode, delete it and run
> `wsl --shutdown`. (A live cross-boundary UDP feed is a possible later
> enhancement; for now we replay the `.tlog`.)

---

## Step 1 — Install WSL2 + Ubuntu (one time)

**Already have Ubuntu?** Skip the install. Just confirm it's on **WSL 2**:

```powershell
wsl -l -v
```

The `VERSION` column must say `2`. If it says `1`, upgrade it:

```powershell
wsl --set-version Ubuntu 2
```

**Fresh install** (only if you don't have it) — PowerShell **as Administrator**:

```powershell
wsl --install -d Ubuntu
```

Reboot if prompted, then launch **Ubuntu** from the Start menu and create your
Linux username/password when asked. Everything from Step 2 onward runs *inside*
this Ubuntu shell.

---

## Step 2 — Install ArduPilot SITL (one time, inside Ubuntu)

```bash
sudo apt update
git clone --recurse-submodules https://github.com/ArduPilot/ardupilot.git
cd ardupilot
Tools/environment_install/install-prereqs-ubuntu.sh -y
. ~/.profile
```

- `--recurse-submodules` pulls ArduPilot's dependencies (it uses several nested
  git repos).
- The `install-prereqs-ubuntu.sh` script installs the compiler and Python tools
  SITL needs, and adds `sim_vehicle.py` to your PATH.
- `. ~/.profile` reloads your shell so the new PATH takes effect **without**
  closing the terminal (the leading dot means "run this in the current shell").

---

## Step 3 — Launch the simulated drone

From inside `~/ardupilot`:

```bash
cd ~/ardupilot/ArduCopter
sim_vehicle.py -w -v ArduCopter --console --map --out=udp:127.0.0.1:14551
```

- `-v ArduCopter` — simulate a multirotor (copter).
- `-w` — wipe the virtual EEPROM to factory defaults. Use it on the **first**
  run only; drop it afterwards to keep your settings.
- `--console` / `--map` — open MAVProxy's status console and a moving map
  (GUI windows; Windows 11's WSLg shows them automatically). Omit both for a
  headless run if you don't want windows.
- `--out=udp:127.0.0.1:14551` — sends an **extra** copy of the MAVLink stream to
  port 14551. Under NAT networking this stays inside WSL, so it is not used by the
  Windows detector today; it is here ready for a future in-WSL live capture. Our
  benign data comes from the `.tlog` (Step 4), not this port.

If SITL fails to bind port 5760 ("Address already in use") on a clean start, you
almost certainly have mirrored networking enabled — see the warning above.

The **first** launch compiles ArduPilot and takes several minutes. When it
finishes you'll see a `STABILIZE>` prompt — that's the MAVProxy command line,
talking to your simulated drone.

---

## Step 4 — Fly one normal (benign) flight

At the `STABILIZE>` prompt, run a simple, legitimate takeoff-and-land. This is
the *normal* behavior our detector must learn to trust:

```text
mode guided
arm throttle
takeoff 20
```

Wait until it climbs to ~20 m, then let it fly for a minute and bring it home:

```text
mode rtl
```

`rtl` = Return To Launch: the drone flies back, lands, and disarms. That whole
sequence — arm, climb, cruise, return, land — is one clean benign flight.

> **If `arm throttle` is rejected** with a prearm error, give the sim ~30–60 s
> after startup for GPS/EKF to settle, then retry. Last resort (simulation only):
> `param set ARMING_CHECK 0`, then `arm throttle`.

---

## Step 5 — Save the capture to the Windows project

MAVProxy has been logging the flight the whole time. Find the log:

```bash
find ~/ardupilot/ArduCopter -name '*.tlog' -newermt '-1 hour' \
  -printf '%T+ %s bytes %p\n' 2>/dev/null | sort
```

Then copy the newest `.tlog` into the project's (git-ignored) `data/benign/`
folder, giving it a clear name:

```bash
mkdir -p /mnt/c/Users/<you>/dev/mavlink-ids/data/benign
cp ~/ardupilot/ArduCopter/mav.tlog \
   /mnt/c/Users/<you>/dev/mavlink-ids/data/benign/benign_flight_01.tlog
```

WSL sees your Windows drive under `/mnt/c`, so this copy crosses to Windows with
no networking involved. Fly more missions and save them as `benign_flight_02`,
etc. — more varied normal flights make a stronger baseline for measuring false
positives later.

### Verify the capture on Windows

From the project folder in a Windows terminal:

```powershell
uv run python -c "from collections import Counter; from mavlink_ids.capture.replay import replay_file; c = Counter(e.msg_type for e in replay_file('data/benign/benign_flight_01.tlog')); print('total events:', sum(c.values())); [print(f'{n:6d}  {t}') for t, n in c.most_common(15)]"
```

You should see tens of thousands of events, dominated by high-rate telemetry
(`ATTITUDE`, `GLOBAL_POSITION_INT`, `RAW_IMU`, …). That confirms the full
parse → replay pipeline works on real data.

