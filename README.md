### *Protect your forms by applying a big tariff on bot submissions.* ###

Each submission can only be submitted alongside a proof of work that consumes a significant amount of both memory and
compute time.

This makes it much more costly to automate submissions.

Some of that cost also applies to regular users, but it should be minimal and even transparent most of the time.

---

Bot mitigation is typically handled by CAPTCHA solutions. However, their effectiveness relies on collecting and
analyzing extensive user data, which poses a significant privacy risk.

This data is used to assess the probability that a user is human and not a bot.
If the probability is too low, the user is either blocked or presented with a series of challenges.

With the advance of AI, bots can now solve those challenges with greater accuracy than most humans,
and at an affordable cost.
This makes challenges unreliable, yet they remain a significant barrier to real users.

Faced with that reality, the only way for CAPTCHA providers to improve their solution is to collect even more data and
increase their reliance on statistical analysis.
This approach inevitably results in plenty of false positives that stop legitimate users,
especially those using privacy services (like VPNs) or unusual browsers.

<br>
Instead of relying on the complexity of puzzle-like challenges, you can replace them with cryptographic challenges
with a controllable cost, letting the browser use system resources to solve them and taking the burden off the user.

For this to work, you have to make those challenges fast enough for the browser to solve
but expensive enough to discourage automation.

The challenge used by this project is a Merkle-tree-based proof of work that is both memory-hard and
computationally-hard.
Even on aging phones, a few cores and a couple hundred megabytes of memory should be available.
Therefore, the challenge is optimized to use these exact resources and solve the cryptographic proof in a few seconds.

Finally, the challenges need to be unique and non-replayable (or at least with very limited replayability).

A common way to achieve this is to use the user form input as a seed.
However, this approach delays the computation until that data is available,
leaving only two undesirable options: make the computation faster and reduce its cost, or force the user to wait.

An alternative is to have the server keep track of the seeds that were already used.
This is tricky to implement cheaply.

The solution used in this project is to allow a large (over half a million)
but finite number of seeds in a rolling time window of 15 minutes.
The server uses two small (64kb) local and unsynchronized bit-vectors to track the consumed seeds.
This design is extremely efficient but allows a challenge to potentially be replayed in the same time window
as many times are there are backend servers. This trade-off should be acceptable for the vast majority of applications.

---

### Building the project ###

```wasm-pack build --target web --release -- --no-default-features --features wasm```
