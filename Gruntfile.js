module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    watch: {
      all: {
        files: './**/*.*',
        tasks: ['shell:rsync'],
        options: {
          livereload: true
        }
      }
    },
    shell: {
      rsync: {
        options: {
          failOnError: false,
          stdout: false,
          stderr: true
        },
        command: 'rsync --exclude=".idea" --exclude="node_modules" -lrvz . oldbook:/var/www/wcsc-csrf; ssh oldbookr "chown -R root:www-data /var/www/wcsc-csrf --silent"'
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-shell');

  // Default task(s).
  grunt.registerTask('default', ['shell:rsync', 'watch']);

};
