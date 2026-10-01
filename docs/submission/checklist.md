# Final-day checklist

Monday 5 October 2026. Every time here is IST, which is UTC+5:30.

- **Deadline:** 23:59 IST, which is 18:29 UTC.
- **Target:** published on Devfolio by 17:00 IST, which is 11:30 UTC.
- A saved draft does not count. The entry must say Published.

Three rules decide every conflict on the day:

1. Publishing beats everything else. If the entry is not published by 16:30, stop
   whatever you are doing and publish.
2. The site never delays Publish. It gets a 45-minute box before Devfolio, and the
   evening after it.
3. Nothing goes out that claims a run, a recording, a relay or a site that did not
   happen. Delete the line instead.

Run every command from the repository root unless a step says otherwise.

## Before Monday

These belong to Sunday in the plan. Tick them before 09:00 on Monday, or move them into
the morning.

- [ ] The 7 Sep handbook is found, and its rules on video length and multi-track entry
      are known. If it is lost, ask hackathon@bitshala.org.
- [ ] The recorded run is done, with the screen captured, following
      [the video script](video-script.md#setting-up-the-run).
- [ ] That run's evidence file is committed under `evidence/`, with the CI test that
      verifies it.
- [ ] The Devfolio draft is saved, with the fields from [devfolio.md](devfolio.md).
- [ ] Wrangler is logged in to Cloudflare, and the Pages project exists. Its address is
      [site URL].

      ```sh
      npx wrangler login
      npx wrangler pages project create canary --production-branch=main
      ```

- [ ] Everything is pushed, and CI passed on the latest commit.

      ```sh
      git status --short
      git push
      gh run list --branch main --limit 3
      ```

## Before 12:00 IST

- [ ] Recount the tests, then update the numbers in the README and in
      [devfolio.md](devfolio.md#numbers) if they moved. The first count is top-level
      tests, the second counts subtests too, and the third is packages.

      ```sh
      go test ./... -count=1 -v -timeout 300s > /tmp/canary-tests.txt 2>&1; echo "exit $?"
      grep -c '^--- PASS' /tmp/canary-tests.txt
      grep -c -- '--- PASS' /tmp/canary-tests.txt
      go list ./... | wc -l
      ```

- [ ] Put the real run's numbers in the README: blocks checked, the time `canary check`
      took, and the evidence file's name and SHA-256.

      ```sh
      ls evidence/*.json
      shasum -a 256 evidence/*.json
      ```

- [ ] The committed evidence file still checks out.

      ```sh
      go run ./cmd/canary verify evidence/[evidence file name, from the run]
      ```

- [ ] Read every hit of a last wording check over the reader-facing pages. "Trustless"
      may appear only as "not trustless".

      ```sh
      grep -nE '§|trustless|secure|guarantee|!' README.md docs/how-canary-works.md docs/faq.md
      ```

## 12:00 IST: freeze

- [ ] Run the full check on a clean tree. Every package must pass.

      ```sh
      git status --short
      go build ./... && go vet ./... && go test ./... -race -count=1 -timeout 300s
      ```

- [ ] From here on, commit only these: the video link, README numbers, the evidence file,
      and typo fixes. No code changes.

## 12:00 to 14:30 IST: record and edit

- [ ] Record the narration in your own voice and edit the video, following
      [the video script](video-script.md).
- [ ] At 13:00, if nothing is recorded yet, record the terminal only, in one take.
- [ ] Check the runtime: at least 3:00, and no more than 4:30.
- [ ] The evidence file in the video matches the committed one.

      ```sh
      shasum -a 256 evidence/[evidence file name, from the run]
      ```

- [ ] Upload to YouTube as Public or Unlisted, never Private. Paste the chapters and the
      description from the video script. The link is [video link].

## 14:30 IST: README video link at the top

- [ ] Add the video link in the README's first lines, above the status section. Then
      commit and push.

      ```sh
      git add README.md
      git commit -m "docs: link the demo video at the top of the README"
      git push
      ```

## 14:40 IST: LICENSE present

- [ ] The file exists and the README's license line points at it.

      ```sh
      head -n 3 LICENSE
      grep -n 'MIT license' README.md
      ```

      The first command prints "MIT License" and "Copyright (c) 2026 the Canary authors".

## 14:45 IST: make the repository public

- [ ] Scan for secrets first. Both commands must print nothing.

      ```sh
      git ls-files | grep -Ei 'nsec|\.key$|\.pem$|(^|/)\.env$|blindbit\.toml$|bitcoin\.conf$'
      git log --all -p | grep -Eo 'nsec1[02-9ac-hj-np-z]{20,}' | head
      ```

- [ ] Make it public, then confirm.

      ```sh
      gh repo edit Sky-walkerX/canary --visibility public --accept-visibility-change-consequences
      gh repo view Sky-walkerX/canary --json visibility -q .visibility
      ```

      The second command prints `PUBLIC`.

## 14:55 IST: tag v0.1.0

- [ ] Tag the commit you submit, and push the tag.

      ```sh
      git tag -a v0.1.0 -m "Canary v0.1.0, the BOSS Battle submission"
      git push origin v0.1.0
      git ls-remote --tags origin v0.1.0
      ```

- [ ] Optional: a GitHub release on the same tag.

      ```sh
      gh release create v0.1.0 --verify-tag --title "Canary v0.1.0" \
        --notes "The BOSS Battle submission. See the README for what works and what does not yet."
      ```

From here until results on 12 Oct, new work goes on a branch. The tag stays as submitted.

## 15:00 to 15:45 IST: build the site and deploy it

The plan puts the public site after Publish. This step tries it first, because Devfolio
wants the link, but only inside this box. At 15:45, stop wherever you are and go to
Devfolio. Come back to the site after 17:00, and stop site work at 21:00.

- [ ] Build the browser checker, then the public site. A build with `-noindex=false`
      refuses to run without the checker, so `make wasm` comes first.

      ```sh
      make wasm
      go run ./cmd/site -noindex=false \
        -evidence evidence/[evidence file name, from the run] \
        -base-url [site URL]
      ```

- [ ] Deploy to the production branch.

      ```sh
      npx wrangler pages deploy site/dist --project-name=canary --branch=main
      ```

- [ ] The site answers, and nothing asks search engines to stay away. The first command
      prints a 200 status. The other two print 0.

      ```sh
      curl -sI [site URL]/ | head -n 1
      curl -s [site URL]/ | grep -c 'name="robots"'
      curl -sI [site URL]/ | grep -ci 'x-robots-tag'
      ```

- [ ] In a private browser window, "Try the real evidence file" reads "Checks out." and
      "Try a tampered copy" does not.

## 15:45 to 16:30 IST: Devfolio fields

- [ ] Open the draft and paste each field from [devfolio.md](devfolio.md).
- [ ] Replace every value in [brackets] in the pasted text. Then search the Devfolio
      preview for "[" and "from the run". Neither may remain.
- [ ] Delete every line whose event did not happen: the real-node run, the committed
      evidence file, the site link.
- [ ] Add the video link, the repository link and, if the site is live, its link.
- [ ] Select Cypherpunk. Add Freedom Stack only if the handbook allows a second track,
      with the Freedom Stack paragraph.

## 16:30 IST: hard stop

- [ ] If the entry is not published yet, stop everything else and publish now.

## By 17:00 IST: Publish

- [ ] Press Publish, not Save draft.
- [ ] The project's status reads Published. Take a screenshot.
- [ ] Open the public project page in a private window and check that it loads.

## 17:00 to 18:00 IST: checks after publishing

- [ ] Every link resolves from a logged-out shell. Each line ends in 200.

      ```sh
      for u in https://github.com/Sky-walkerX/canary \
               https://github.com/Sky-walkerX/canary/blob/v0.1.0/LICENSE \
               [video link] [site URL]; do
        printf '%s ' "$u"; curl -s -o /dev/null -L -w '%{http_code}\n' "$u"
      done
      ```

      YouTube answers 200 even for a private video, so also open the video link in a
      private window and press play.

- [ ] CI passed on the tagged commit.

      ```sh
      gh run list --commit "$(git rev-parse 'v0.1.0^{commit}')" --limit 5
      ```

      If the run is still going, watch it with `gh run watch`.

- [ ] The README on GitHub shows the video link at the top, and the link plays.
- [ ] The site is reachable, if it was deployed. If not, deploy it now with the 15:00
      steps, then add its link to Devfolio if the form still allows edits.
- [ ] The Devfolio page shows the right track, the video and the repository link.

## 21:00 IST: stop site work

- [ ] Whatever state the site is in, leave it.

## 21:00 to 23:59 IST: emergencies only

Touch nothing unless a link is broken or the entry is not published. The deadline is
23:59 IST, which is 18:29 UTC. Results come out on Monday 12 October at 14:00 IST.
