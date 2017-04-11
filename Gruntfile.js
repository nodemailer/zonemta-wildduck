'use strict';

module.exports = function (grunt) {

    // Project configuration.
    grunt.initConfig({
        eslint: {
            all: ['Gruntfile.js', 'index.js']
        }
    });

    // Load the plugin(s)
    grunt.loadNpmTasks('grunt-eslint');

    // Tasks
    grunt.registerTask('default', ['eslint']);
};
