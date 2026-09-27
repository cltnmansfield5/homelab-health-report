# Third-party notices

The MIT license in this repository covers the owner's original code,
configuration and documentation. It does not relicense referenced container
images, bundled dependencies, trademarks, or copied upstream material.

Container image publishers retain their own licenses. Review the exact image's
source and license before redistributing an image or making modifications.
The deployment files pull those images; this repository is not their source.

The uploader image builds rclone and copies its upstream `COPYING` file to
`/usr/share/licenses/rclone/COPYING`. rclone and its Go dependencies retain their
respective licenses. Python, Go and Alpine base images also retain their terms.
Source: https://github.com/rclone/rclone
