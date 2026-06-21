// Trivial source so the kotlin compiler artifacts are exercised + cached at image
// build time. Not shipped; the prefetch project is a throwaway dependency seed.
package prefetch

fun seed(): Int = 42
