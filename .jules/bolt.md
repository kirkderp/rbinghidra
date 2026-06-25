- Date: 2024-05-24
  Title: Avoid Unnecessary Object Clones
  Learning: Hot paths should use references instead of passing cloned complex objects to avoid unnecessary memory allocations.
  Action: Replaced string/path cloning with references in `ProcessSpec`.
