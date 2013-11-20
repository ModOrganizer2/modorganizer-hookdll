import qbs.base 1.0
import qbs.File
import "../commonfunctions.js" as Common

DynamicLibrary {
    name: 'hookdll'

    Depends { name: 'cpp' }
    Depends { name: 'BSAToolkit' }
    Depends { name: 'Shared' }

    cpp.defines: [ '_WINDLL' ]

    cpp.libraryPaths: [ qbs.getenv('BOOSTPATH') + '/stage/lib' ].concat(Common.zlibLibraryPaths(qbs))
    cpp.staticLibraries: [ 'user32', 'shell32', 'ole32', 'Version', 'shlwapi' ].concat(Common.zlibLibs(qbs))
    cpp.includePaths: [ '../shared', '../bsatk', qbs.getenv("BOOSTPATH") ]

    files: [
        '*.cpp',
        '*.h'
    ]
}
