package org.dxworks.dependencyminer

data class DependencyFile (
    val java: List<String>,
    val javascript: List<String>,
    val php: List<String>,
    val ruby: List<String>,
    val python: List<String>
)