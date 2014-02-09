mkdir chrisandrews-set$SET
find lib subset$SET -name '*.p[lm]' | rsync --files-from=- -vr . chrisandrews-set$SET/
tar zcvf chrisandrews-set$SET.tar.gz chrisandrews-set$SET
rm -rf chrisandrews-set$SET
