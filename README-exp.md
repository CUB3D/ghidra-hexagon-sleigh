git log \
  --pretty=email \
  --patch-with-stat \
  --reverse \
  --full-index \
  --binary \
  -m \
  --first-parent \
  -- . \
  > patch

git am --committer-date-is-author-date -p2 < ../old_random_projects_archive/eclipse-workspace-qcom/patch
git filter-repo --invert-paths --force --path sample_files
git filter-repo --invert-paths --force --path Hexagon/.idea
git filter-repo --invert-paths --force --path Hexagon/data/languages/skel.sla
git filter-repo --invert-paths --force --path Hexagon/.gradle
git filter-repo --invert-paths --force --path Hexagon/dist
git filter-repo --invert-paths --force --path Hexagon/build
git filter-repo --invert-paths --force --path Hexagon/.antProperties.xml
git filter-repo --invert-paths --force --path Hexagon/.classpath
git filter-repo --invert-paths --force --path Hexagon/.project
git filter-repo --invert-paths --force --path Hexagon/.settings
git filter-repo --invert-paths --force --path .metadata
git filter-repo --invert-paths --force --path .settings

