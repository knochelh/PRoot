if [ ! -x  ${ROOTFS}/bin/true ]; then
    exit 125;
fi

${PROOT} -w /bin ${ROOTFS} ./true

