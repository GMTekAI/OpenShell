{
  libkrun,
  openshellLibkrunfw,
}:

libkrun.override {
  libkrunfw = openshellLibkrunfw;
  withBlk = true;
  withNet = true;
  withGpu = false;
}
