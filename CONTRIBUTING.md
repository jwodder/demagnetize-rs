Golden Rules
============

1. Submissions generated in whole or in part by an LLM or other generative AI
   will NOT be accepted.

    - Being deceptive about the origin of AI-generated code will get you banned
      for life from all of my repositories.

    - All comments on GitHub issues & pull requests are expected to be written
      by a human and must not be direct output from an AI.

2. No pull request will be accepted unless all of the tests pass.

    - New contributors will have to wait for their PRs to be manually approved
      before GitHub Actions will test their contributions.  The wait should be
      no longer than 24 hours.

3. Lint your code!  Install [pre-commit](https://pre-commit.com) on your
   machine, run `pre-commit install` in your local clone of the repository, and
   then let pre-commit automatically format & lint the code before each commit.

4. If making a nontrivial contribution, add tests!

5. If adding or changing a public-facing feature, be sure to add or adjust doc
   comments.

6. If making a nontrivial contribution, add a summary to the "in development"
   section at the top of `CHANGELOG.md` (if there isn't one, start one);
   include your GitHub username and any issues that your PR closes.

    - I am aware that having everyone edit the same file could lead to merge
      conflicts, but until contributions become frequent enough that it's a
      recurring problem, manually editing `CHANGELOG.md` should be fine.  If
      it's not, we'll switch to towncrier or similar.
